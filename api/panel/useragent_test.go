package panel

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/common/serverstatus"
	"github.com/PoriyaVali/V2bX/conf"
)

// The panel can only tell which build a node runs from what the node sends.
// Every request - polls, reports, status - must carry the version.
func TestEveryPanelRequestNamesTheBuild(t *testing.T) {
	old := userAgent
	t.Cleanup(func() { userAgent = old })
	SetVersion("v9.9.9")

	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("User-Agent")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer srv.Close()

	c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "k", NodeType: "anytls", Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ReportNodeStatus(&serverstatus.SystemStatus{CPU: 1}); err != nil {
		t.Fatal(err)
	}
	if err := c.ReportUserTraffic(nil); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no request reached the panel")
	}
	for path, ua := range seen {
		if ua != "V2bX/v9.9.9" {
			t.Errorf("%s: User-Agent %q, want %q", path, ua, "V2bX/v9.9.9")
		}
	}
}

func TestSetVersionIgnoresAnEmptyVersion(t *testing.T) {
	old := userAgent
	t.Cleanup(func() { userAgent = old })
	userAgent = "V2bX"
	SetVersion("  ")
	if userAgent != "V2bX" {
		t.Fatalf("User-Agent %q after an empty version, want the plain name", userAgent)
	}
}
