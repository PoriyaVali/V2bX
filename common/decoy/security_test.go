package decoy

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func request(h http.Handler, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCoverIdentitySurvivesNodeChangesAndLinksWork(t *testing.T) {
	first := Handler(Identity("Notes.Example.Test.", "", "one-core"))
	second := Handler(Identity("notes.example.test", "", "another-core"))
	a, b := request(first, "GET", "/", nil), request(second, "GET", "/", nil)
	if a.Body.String() != b.Body.String() || a.Header().Get("ETag") != b.Header().Get("ETag") || a.Header().Get("Last-Modified") != b.Header().Get("Last-Modified") {
		t.Fatal("one domain showed different sites across nodes")
	}
	links := regexp.MustCompile(`(?:href|src)="([^"]+)"`).FindAllStringSubmatch(a.Body.String(), -1)
	if len(links) < 6 {
		t.Fatal("site has no useful navigation/assets")
	}
	for _, link := range links {
		r := request(first, "GET", link[1], nil)
		if r.Code != 200 {
			t.Errorf("broken link %s: %d", link[1], r.Code)
		}
	}
	if a.Header().Get("Server") != "" || strings.Contains(a.Body.String(), "V2bX") {
		t.Fatal("public response exposes implementation")
	}
}

func TestCoverStaticHTTPConditionalHeadRangeAndCompression(t *testing.T) {
	h := Handler("http-contract")
	// Select the actual article from this site's index, independent of profile.
	index := request(h, "GET", "/", nil)
	article := regexp.MustCompile(`href="(/posts/[^"]+)"`).FindStringSubmatch(index.Body.String())[1]
	full := request(h, "GET", article, nil)
	if full.Code != 200 {
		t.Fatal("article unavailable")
	}
	for _, headers := range []map[string]string{{"If-None-Match": full.Header().Get("ETag")}, {"If-None-Match": "W/" + full.Header().Get("ETag")}, {"If-None-Match": "\"other\", " + full.Header().Get("ETag")}, {"If-Modified-Since": full.Header().Get("Last-Modified")}} {
		r := request(h, "GET", article, headers)
		if r.Code != 304 || r.Body.Len() != 0 {
			t.Fatalf("bad conditional response: %d / %d", r.Code, r.Body.Len())
		}
	}
	head := request(h, "HEAD", article, nil)
	if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(full.Body.Len()) {
		t.Fatal("HEAD differs from GET metadata")
	}
	partial := request(h, "GET", article, map[string]string{"Range": "bytes=0-23"})
	if partial.Code != 206 || partial.Body.String() != full.Body.String()[:24] {
		t.Fatal("byte range did not select resource bytes")
	}
	compressed := request(h, "GET", article, map[string]string{"Accept-Encoding": "gzip"})
	if compressed.Header().Get("Content-Encoding") != "gzip" || compressed.Header().Get("ETag") == full.Header().Get("ETag") {
		t.Fatal("gzip representation metadata is inconsistent")
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(data) != full.Body.String() {
		t.Fatal("compressed page differs")
	}
	if r := request(h, "GET", article, map[string]string{"Accept-Encoding": "gzip;q=0, *;q=1"}); r.Header().Get("Content-Encoding") != "" {
		t.Fatal("explicit gzip refusal ignored")
	}
	if r := request(h, "GET", article, map[string]string{"Accept-Encoding": "gzip", "If-None-Match": compressed.Header().Get("ETag")}); r.Code != 304 || r.Body.Len() != 0 {
		t.Fatal("gzip ETag validation failed")
	}
	post := request(h, "POST", article, nil)
	if post.Code != 405 || post.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("static site accepted a write method")
	}
}

func TestPublicRootCannotServeKeysConfigDirectoryListingsOrSymlinks(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"index.html": "<html><title>Owner site</title>owner</html>", "assets/site.css": "body{color:navy}", ".env": "SECRET=private", "private.key": "private key", "config.json": "private API key", "dns.json": "private DNS token", "credentials.txt": "private password", "folder/entry.html": "public entry"} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, ".env"), filepath.Join(dir, "leak.html")); err != nil {
		t.Logf("symlink unavailable: %v", err)
	}
	h, err := HandlerWithConfig("owner", &Config{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r := request(h, "GET", "/", nil); r.Code != 200 || !strings.Contains(r.Body.String(), "Owner site") {
		t.Fatal("owner's index not served")
	}
	for _, path := range []string{"/.env", "/private.key", "/config.json", "/dns.json", "/credentials.txt", "/folder/", "/leak.html", "/../.env", "/%2e%2e/.env"} {
		if r := request(h, "GET", path, nil); r.Code != 404 || strings.Contains(r.Body.String(), "private") {
			t.Errorf("private path exposed: %s (%d)", path, r.Code)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("changed on disk"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := request(h, "GET", "/", nil); !strings.Contains(r.Body.String(), "Owner site") {
		t.Fatal("request read changing disk content outside the snapshot")
	}
}

func TestInvalidPublicRootFailsBeforeBinding(t *testing.T) {
	if site, err := StartWithConfig("bad", &Config{Root: t.TempDir()}); err == nil {
		site.Close()
		t.Fatal("root without index silently fell back")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), make([]byte, maxFileBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := HandlerWithConfig("too-large", &Config{Root: dir}); err == nil {
		t.Fatal("oversized public asset accepted")
	}
}

func TestCoverRequestBudgetReturnsOrdinaryOverloadResponse(t *testing.T) {
	h, err := HandlerWithConfig("quota", &Config{RequestsPerSecond: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if r := request(h, "GET", "/", nil); r.Code != 200 {
			t.Fatal("burst allowance unavailable")
		}
	}
	r := request(h, "GET", "/", nil)
	if r.Code != 503 || r.Header().Get("Retry-After") != "1" {
		t.Fatal("unbounded public request rate")
	}
}

func siteCertificate(t *testing.T) (string, string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"node.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, cert
}

func TestTCPCompanionUsesOwnedCertificateHTTP2AndJoinedLifecycle(t *testing.T) {
	cert, key, certPEM := siteCertificate(t)
	if Identity("", cert, "first") != Identity("node.example.test", "", "second") {
		t.Fatal("certificate SAN did not identify the domain")
	}
	d, err := Start(Identity("node.example.test", "", "node"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.StartTLSCompanion("127.0.0.1:0", cert, key); err != nil {
		t.Fatal(err)
	}
	address := d.companion.Addr()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "node.example.test", MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	r, err := client.Get("https://" + address + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.ProtoMajor != 2 || r.StatusCode != 200 || !strings.Contains(string(body), "<title>") {
		t.Fatalf("bad TLS website response: %s %d", r.Proto, r.StatusCode)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("public listener outlived node")
	}
	if err := d.StartTLSCompanion("127.0.0.1:0", cert, key); err == nil {
		t.Fatal("closed site created a listener")
	}
}

func TestTCPCompanionDoesNotReplaceAnExistingListener(t *testing.T) {
	cert, key, _ := siteCertificate(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	d, err := Start("occupied")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.StartTLSCompanion(occupied.Addr().String(), cert, key); err == nil {
		t.Fatal("occupied TCP address was replaced")
	}
	if r := request(d.server.Handler, "GET", "/", nil); r.Code != 200 {
		t.Fatal("TCP conflict broke the cover handler")
	}
}
