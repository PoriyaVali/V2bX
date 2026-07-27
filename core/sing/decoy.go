package sing

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PoriyaVali/V2bX/common/format"
	log "github.com/sirupsen/logrus"
)

// A decoy site, served by V2bX itself.
//
// An anytls listener that completes the TLS handshake and then closes the
// moment the password does not match answers nothing like a web server, and
// that is exactly what an active prober looks for: connect, speak TLS, send an
// ordinary GET, see what comes back. Nothing did, so the port was a tell.
//
// The inbound's fallback now points here instead, and this serves a small,
// ordinary-looking site. Deliberately in-process: needing an nginx per node
// would mean ten manual installs, a second service to keep running, and a
// config that drifts. Everything here ships with the binary.
//
// Two rules the design follows:
//
//  1. **Never impersonate a real organisation.** A page copying a real
//     company would be both a legal problem and a weaker disguise - a prober
//     can diff it against the genuine site. These are plain, unremarkable
//     pages that claim to be nobody.
//
//  2. **Different per node.** Ten nodes serving one identical page just moves
//     the fingerprint: the repetition itself becomes the signature. The
//     template and its details are picked deterministically from the node's
//     own identity, so each node keeps its own site across restarts without
//     an operator choosing anything.
type decoy struct {
	listener net.Listener
	server   *http.Server
	addr     string
	once     sync.Once
}

// decoyTemplate is one plausible site. Kept intentionally dull: a site with
// nothing to say attracts no follow-up.
type decoyTemplate struct {
	title    string
	heading  string
	tagline  string
	sections []string
	footer   string
}

var decoyTemplates = []decoyTemplate{
	{
		title:   "Aperture Notes",
		heading: "Aperture Notes",
		tagline: "Field notes on light, film and slow photography.",
		sections: []string{
			"On metering for shadow detail",
			"Developing at home without a darkroom",
			"Why I went back to a fixed lens",
		},
		footer: "Written irregularly. No newsletter, no tracking.",
	},
	{
		title:   "The Proof Kitchen",
		heading: "The Proof Kitchen",
		tagline: "Bread, mostly. Occasionally something else.",
		sections: []string{
			"A sourdough starter that survives neglect",
			"Hydration, and why the number lies",
			"Cold ferment: a schedule for people with jobs",
		},
		footer: "Recipes are tested at home, in an ordinary oven.",
	},
	{
		title:   "Ledger & Line",
		heading: "Ledger & Line",
		tagline: "Small tools for small businesses.",
		sections: []string{
			"Invoices that do not need an account",
			"A stock counter for one shelf",
			"Export everything, always",
		},
		footer: "Independent. Nothing here phones home.",
	},
	{
		title:   "Two Rivers Cycling",
		heading: "Two Rivers Cycling",
		tagline: "Routes, repairs and weekend rides.",
		sections: []string{
			"A loop that avoids every main road",
			"Truing a wheel with the frame as your gauge",
			"Winter gloves: an unscientific comparison",
		},
		footer: "Ride reports posted when the weather allows.",
	},
	{
		title:   "Quiet Hours Audio",
		heading: "Quiet Hours Audio",
		tagline: "Listening notes and room acoustics.",
		sections: []string{
			"Treating a room you are not allowed to drill",
			"Why the first reflection matters most",
			"A cheap measurement microphone, tested",
		},
		footer: "No affiliate links. Opinions are stubbornly personal.",
	},
	{
		title:   "Marginalia Press",
		heading: "Marginalia Press",
		tagline: "A very small publisher of very short books.",
		sections: []string{
			"Our next four titles",
			"Submissions: what we actually read",
			"On printing in runs of two hundred",
		},
		footer: "Set in Georgia. Printed on paper.",
	},
	{
		title:   "Northwind Allotments",
		heading: "Northwind Allotments",
		tagline: "Notes from plot 14.",
		sections: []string{
			"Tomatoes that survived a bad August",
			"Composting when you have no space",
			"A watering rota that nobody follows",
		},
		footer: "Updated whenever there is something to report.",
	},
	{
		title:   "Sable & Co Joinery",
		heading: "Sable & Co Joinery",
		tagline: "Hand-cut furniture, made to order.",
		sections: []string{
			"A bench that fits through a doorway",
			"Choosing between oak and ash",
			"Lead times and how we quote",
		},
		footer: "Workshop visits by arrangement.",
	},
}

// pick derives a stable template + accent from the node's own identity, so a
// node keeps the same site across restarts and two nodes rarely share one.
func pickDecoy(seed string) (decoyTemplate, string, time.Time) {
	sum := sha256.Sum256([]byte(seed))
	idx := int(binary.BigEndian.Uint32(sum[0:4])) % len(decoyTemplates)
	if idx < 0 {
		idx += len(decoyTemplates)
	}
	accents := []string{"#2f4858", "#33658a", "#55606e", "#3d5a54", "#6b4d3b", "#4a4e69"}
	accent := accents[int(sum[4])%len(accents)]
	// A plausible "last updated" that is stable per node and comfortably in the
	// past: a site whose only page changed one second ago reads as generated.
	days := 30 + int(sum[5])%300
	built := time.Now().AddDate(0, 0, -days).Truncate(time.Hour)
	return decoyTemplates[idx], accent, built
}

func renderDecoy(t decoyTemplate, accent string, built time.Time) string {
	var items strings.Builder
	for _, s := range t.sections {
		fmt.Fprintf(&items, "      <li><a href=\"/posts/%s\">%s</a></li>\n", slugify(s), s)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
  body { margin: 0; font: 16px/1.6 Georgia, 'Times New Roman', serif; color: #222; background: #fbfbf9; }
  .wrap { max-width: 42rem; margin: 0 auto; padding: 3rem 1.25rem; }
  h1 { font-size: 1.9rem; margin: 0 0 .25rem; color: %s; }
  p.tag { margin: 0 0 2.5rem; color: #666; }
  ul { list-style: none; padding: 0; }
  li { padding: .6rem 0; border-bottom: 1px solid #e8e6e0; }
  a { color: %s; text-decoration: none; }
  a:hover { text-decoration: underline; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e8e6e0; color: #888; font-size: .9rem; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>%s</h1>
    <p class="tag">%s</p>
    <ul>
%s    </ul>
    <footer>%s<br>Last updated %s.</footer>
  </div>
</body>
</html>
`, t.title, accent, accent, t.heading, t.tagline, items.String(), t.footer, built.Format("2 January 2006"))
}

func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// startDecoy binds a loopback listener and serves the site. The port is chosen
// by the OS so nothing has to be reserved or configured, and it is loopback
// only: a decoy reachable from outside on its own port would be a fresh tell,
// since the site would then exist twice on one host.
func startDecoy(seed string) (*decoy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen decoy: %w", err)
	}
	tpl, accent, built := pickDecoy(seed)
	page := renderDecoy(tpl, accent, built)
	etag := `"` + hex.EncodeToString(sha256.New().Sum([]byte(page))[:8]) + `"`

	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, r *http.Request, status int, body, ctype string) {
		h := w.Header()
		h.Set("Content-Type", ctype)
		// Real sites announce a server. Go sends no Server header at all,
		// which is itself unusual enough to notice.
		h.Set("Server", "nginx")
		h.Set("Last-Modified", built.UTC().Format(http.TimeFormat))
		if status == http.StatusOK {
			h.Set("ETag", etag)
			if match := r.Header.Get("If-None-Match"); match == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		h.Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(status)
		// HEAD must carry the headers and no body; net/http drops the body for
		// us, but writing it explicitly keeps Content-Length honest.
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
	}

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		write(w, r, http.StatusOK, "User-agent: *\nDisallow:\n", "text/plain; charset=utf-8")
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		write(w, r, http.StatusNotFound, "", "text/plain; charset=utf-8")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			write(w, r, http.StatusOK, page, "text/html; charset=utf-8")
			return
		}
		// Anything else 404s with an ordinary page. A server that answers 200
		// for every path is as odd as one that answers nothing.
		body := "<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>\n" +
			"<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n"
		write(w, r, http.StatusNotFound, body, "text/html; charset=utf-8")
	})

	d := &decoy{
		listener: ln,
		addr:     ln.Addr().String(),
		server: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       30 * time.Second,
		},
	}
	go func() {
		if err := d.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.WithField("err", err).Warn("decoy site stopped")
		}
	}()
	log.WithFields(log.Fields{
		"site": tpl.title,
		"addr": d.addr,
	}).Info("decoy site serving unauthenticated connections")
	return d, nil
}

func (d *decoy) Close() error {
	if d == nil {
		return nil
	}
	var err error
	d.once.Do(func() {
		err = d.server.Close()
	})
	return err
}

// Host and Port split for building the sing-box fallback ServerOptions.
func (d *decoy) hostPort() (string, uint16) {
	host, portStr, err := net.SplitHostPort(d.addr)
	if err != nil {
		return "127.0.0.1", 0
	}
	var port uint16
	_, _ = fmt.Sscan(portStr, &port)
	return host, port
}

// decoySeed keeps the site stable for a node: same node, same site, restart
// after restart. format.UserTag-style joining keeps it readable in logs.
func decoySeed(tag string) string {
	return format.UserTag("decoy", tag)
}
