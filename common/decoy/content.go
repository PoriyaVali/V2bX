package decoy

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Config controls the public cover site only, never authenticated proxy traffic.
type Config struct {
	Root              string `json:"Root,omitempty"`
	Title             string `json:"Title,omitempty"`
	MaxConnections    int    `json:"MaxConnections,omitempty"`
	RequestsPerSecond int    `json:"RequestsPerSecond,omitempty"`
	ServeTCP          *bool  `json:"ServeTCP,omitempty"`
}

func (c *Config) TCPEnabled() bool { return c == nil || c.ServeTCP == nil || *c.ServeTCP }

const (
	maxSiteFiles = 256
	maxFileBytes = 2 << 20
	maxSiteBytes = 16 << 20
)

type resource struct {
	body, compressed            []byte
	contentType, etag, gzipETag string
	modified                    time.Time
}

func makeResource(body []byte, contentType string, modified time.Time) *resource {
	r := &resource{body: body, contentType: contentType, modified: modified.UTC().Truncate(time.Second)}
	etag := func(data []byte) string { sum := sha256.Sum256(data); return `"` + hex.EncodeToString(sum[:16]) + `"` }
	r.etag = etag(body)
	if len(body) >= 1024 && (strings.HasPrefix(contentType, "text/") || strings.Contains(contentType, "json") || strings.Contains(contentType, "xml")) {
		var compressed bytes.Buffer
		writer, _ := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
		_, _ = writer.Write(body)
		_ = writer.Close()
		if compressed.Len()+128 < len(body) {
			r.compressed = compressed.Bytes()
			r.gzipETag = etag(r.compressed)
		}
	}
	return r
}

// HandlerWithConfig snapshots public assets at node creation. Requests never
// read arbitrary paths, list directories, execute files or dial another host.
func HandlerWithConfig(seed string, config *Config) (http.Handler, error) {
	if config == nil {
		config = &Config{}
	}
	if len(config.Title) > 256 || config.MaxConnections < 0 || config.MaxConnections > 4096 || config.RequestsPerSecond < 0 || config.RequestsPerSecond > 10000 {
		return nil, fmt.Errorf("invalid cover-site resource limits")
	}
	files, title, built := generatedResources(seed, config.Title)
	if config.Root != "" {
		var err error
		files, err = loadPublicFiles(config.Root)
		if err != nil {
			return nil, err
		}
		title = config.Title
	}
	// Error responses are cached too: a request flood must not render pages.
	errorBodies := make(map[int][]byte, 3)
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusServiceUnavailable} {
		label := http.StatusText(status)
		errorBodies[status] = []byte(fmt.Sprintf(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>%s</title></head><body><h1>%s</h1><p>%s</p><p><a href="/">Home</a></p></body></html>`, label, label, html.EscapeString(title)))
	}
	writeError := func(w http.ResponseWriter, r *http.Request, status int) {
		body := errorBodies[status]
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
	requests := config.RequestsPerSecond
	if requests == 0 {
		requests = 128
	}
	limiter := rate.NewLimiter(rate.Limit(requests), 2*requests)
	active := make(chan struct{}, 64)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			writeError(w, r, http.StatusServiceUnavailable)
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeError(w, r, http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, r, http.StatusMethodNotAllowed)
			return
		}
		item := files[r.URL.Path]
		if item == nil {
			writeError(w, r, http.StatusNotFound)
			return
		}
		body, etag := item.body, item.etag
		if item.compressed != nil {
			w.Header().Set("Vary", "Accept-Encoding")
			if r.Header.Get("Range") == "" && acceptsGzip(r.Header.Get("Accept-Encoding")) {
				body, etag = item.compressed, item.gzipETag
				w.Header().Set("Content-Encoding", "gzip")
			}
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", item.contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if strings.Count(r.Header.Get("Range"), ",") > 15 {
			r = r.Clone(r.Context())
			r.Header.Del("Range")
		}
		modified := item.modified
		if modified.IsZero() {
			modified = built
		}
		http.ServeContent(w, r, "", modified, bytes.NewReader(body))
	}), nil
}

func acceptsGzip(value string) bool {
	wildcard := false
	for _, part := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(part), ";")
		q := 1.0
		for _, parameter := range parts[1:] {
			key, v, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && strings.EqualFold(key, "q") {
				parsed, err := strconv.ParseFloat(v, 64)
				if err != nil || parsed < 0 || parsed > 1 {
					q = 0
				} else {
					q = parsed
				}
			}
		}
		if strings.EqualFold(parts[0], "gzip") {
			return q > 0
		}
		if parts[0] == "*" && q > 0 {
			wildcard = true
		}
	}
	return wildcard
}

const styleSheet = `:root{color-scheme:light}body{margin:0;background:#faf9f6;color:#252b30;font:17px/1.75 Georgia,serif}main{max-width:44rem;margin:auto;padding:3rem 1.4rem}header{border-bottom:1px solid #dcdad3;padding-bottom:1rem;margin-bottom:2rem}header a{text-decoration:none;color:inherit}h1{font-size:2rem;line-height:1.25}p.subtitle,footer{color:#666}a{color:#355c68}li{margin:1rem 0}article{margin:2rem 0}footer{border-top:1px solid #dcdad3;margin-top:3rem;padding-top:1rem;font-size:.85rem}nav a{margin-right:1rem}@media(max-width:540px){main{padding:1.5rem 1rem}h1{font-size:1.6rem}}`

func renderPage(title, heading, tagline, content, footer string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>%s</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/site.css"></head><body><main><header><a href="/">%s</a><nav><a href="/">Notes</a><a href="/about">About</a></nav></header><h1>%s</h1><p class="subtitle">%s</p>%s<footer>%s</footer></main></body></html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(heading), html.EscapeString(tagline), content, html.EscapeString(footer))
}

func generatedResources(seed, title string) (map[string]*resource, string, time.Time) {
	tpl, accent, built := pickDecoy(seed)
	if title == "" {
		title = tpl.title
	}
	tpl.footer += " Updated " + built.Format("2 January 2006") + "."
	files := map[string]*resource{}
	add := func(url, body, kind string) { files[url] = makeResource([]byte(body), kind, built) }
	var list strings.Builder
	for i, section := range tpl.sections {
		url := "/posts/" + slugify(section)
		fmt.Fprintf(&list, `<li><a href="%s">%s</a></li>`, url, html.EscapeString(section))
		paragraphs := []string{
			"The most useful notes begin with something small enough to try again. This entry keeps the assumptions beside the result, rather than treating a single good afternoon as a general rule.",
			"I start with what is already available, change one thing and keep a short record. It is easier to notice what matters when the comparison is simple and the conditions are written down.",
			"The details are worth revisiting after a few weeks. A method that still makes sense on an ordinary busy day is usually more useful than an impressive result that cannot be repeated.",
		}
		content := `<article><p>` + html.EscapeString(tpl.tagline) + `</p>`
		for j := 0; j < 2; j++ {
			content += `<p>` + paragraphs[(i+j)%len(paragraphs)] + `</p>`
		}
		content += `</article><p><a href="/">All notes</a></p>`
		add(url, renderPage(title, section, built.Format("2 January 2006"), content, tpl.footer), "text/html; charset=utf-8")
	}
	add("/", renderPage(title, title, tpl.tagline, "<ul>"+list.String()+"</ul>", tpl.footer), "text/html; charset=utf-8")
	add("/about", renderPage(title, "About these notes", tpl.tagline, `<p>A small collection of practical observations, updated when there is something worth keeping.</p><p>No account is required to read these pages.</p>`, tpl.footer), "text/html; charset=utf-8")
	files["/about/"] = files["/about"]
	add("/assets/site.css", styleSheet, "text/css; charset=utf-8")
	add("/robots.txt", "User-agent: *\nDisallow:\n", "text/plain; charset=utf-8")
	add("/favicon.svg", fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="%s"/><path d="M18 18h28v5H18zm0 12h22v5H18zm0 12h28v5H18z" fill="white"/></svg>`, accent), "image/svg+xml")
	return files, title, built
}

func publicFile(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	base := strings.ToLower(path.Base(name))
	switch base {
	case "config.json", "credentials.json", "package.json", "package-lock.json", "composer.json", "composer.lock":
		return false
	}
	if path.Ext(base) == ".txt" {
		return base == "robots.txt" || base == "security.txt" || base == "humans.txt" || base == "ads.txt"
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".htm", ".css", ".js", ".mjs", ".svg", ".ico", ".png", ".jpg", ".jpeg", ".webp", ".avif", ".gif", ".woff", ".woff2", ".xml":
		return true
	}
	return false
}

func loadPublicFiles(directory string) (map[string]*resource, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open cover-site root: %w", err)
	}
	defer root.Close()
	files := map[string]*resource{}
	total := int64(0)
	visited := 0
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > 4096 {
			return fmt.Errorf("cover-site directory contains too many entries")
		}
		if name == "." {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !publicFile(name) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if len(files) >= maxSiteFiles || info.Size() > maxFileBytes {
			return fmt.Errorf("cover-site public assets exceed file limits")
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
		_ = f.Close()
		if err != nil {
			return err
		}
		total += int64(len(data))
		if len(data) > maxFileBytes || total > maxSiteBytes {
			return fmt.Errorf("cover-site public assets exceed memory budget")
		}
		kind := mime.TypeByExtension(path.Ext(name))
		if kind == "" {
			kind = "application/octet-stream"
		}
		files["/"+name] = makeResource(data, kind, info.ModTime())
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load cover-site public files: %w", err)
	}
	for name, item := range files {
		if strings.HasSuffix(name, "/index.html") {
			files[strings.TrimSuffix(name, "index.html")] = item
		}
	}
	if files["/"] == nil {
		return nil, fmt.Errorf("cover-site root requires index.html")
	}
	return files, nil
}
