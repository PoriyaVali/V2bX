package sing

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func decoyGet(t *testing.T, seed, path string) *http.Response {
	t.Helper()
	d, err := startDecoy(seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	resp, err := http.Get("http://" + d.addr + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// Every node's decoy used to send the same ETag: sha256.New().Sum(page)
// appends the hash of NOTHING to the page, and the first 8 bytes of that are
// the page's own "<!DOCTYP". One header value then identified the whole fleet
// to an active prober. It must differ per site and look like nginx's own
// "<mtime hex>-<size hex>".
func TestDecoy_ETagIsPerSiteAndNginxShaped(t *testing.T) {
	seen := map[string]string{}
	nginxETag := regexp.MustCompile(`^"[0-9a-f]+-[0-9a-f]+"$`)
	for _, seed := range []string{"node-a", "node-b", "node-c", "node-d", "node-e", "node-f"} {
		resp := decoyGet(t, seed, "/")
		etag := resp.Header.Get("ETag")
		if !nginxETag.MatchString(etag) {
			t.Fatalf("seed %s: ETag %q is not nginx-shaped", seed, etag)
		}
		if other, dup := seen[etag]; dup {
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), "<title>") || other == "" {
				t.Fatalf("seed %s: no page", seed)
			}
			t.Fatalf("seeds %s and %s send the same ETag %s", seed, other, etag)
		}
		seen[etag] = seed
	}
}

// The Server header says nginx, so a 404 must be nginx's own page - it was
// Apache's wording, which gives the disguise away.
func TestDecoy_404IsNginxs(t *testing.T) {
	resp := decoyGet(t, "node-a", "/nope")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<center>nginx</center>") || strings.Contains(string(body), "requested URL") {
		t.Fatalf("404 page is not nginx's:\n%s", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html" {
		t.Fatalf("404 Content-Type %q, nginx sends text/html", ct)
	}
}
