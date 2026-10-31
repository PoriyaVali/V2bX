package panel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/common/serverstatus"
	"github.com/PoriyaVali/V2bX/conf"
)

// The status report carries the node's health beside the server's load; the
// error reaches the admin page, so it carries no token and is bounded.
func TestReportNodeHealthShape(t *testing.T) {
	var got map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.Write([]byte(`{"data":true}`))
	}))
	defer srv.Close()
	c, err := New(&conf.ApiConfig{APIHost: srv.URL, Key: "secret-token", NodeID: 3, NodeType: "sudoku", Timeout: 2})
	if err != nil {
		t.Fatal(err)
	}
	problem := "listen tcp :443: bind: address already in use (token=secret-token) " + strings.Repeat("x", 400)
	if err := c.ReportNodeHealth(&serverstatus.SystemStatus{CPU: 7}, &NodeHealth{Serving: false, Users: 2, Error: problem}); err != nil {
		t.Fatal(err)
	}
	if string(got["cpu"]) != "7" {
		t.Fatalf("load not at the top level: %s", got["cpu"])
	}
	var health NodeHealth
	if err := json.Unmarshal(got["node"], &health); err != nil {
		t.Fatal(err)
	}
	if health.Serving || health.Users != 2 || strings.Contains(health.Error, "secret-token") || len([]rune(health.Error)) != 300 {
		t.Fatalf("health sent as %+v", health)
	}
	// Without health the report is the plain load, as older panels expect.
	got = nil
	if err := c.ReportNodeStatus(&serverstatus.SystemStatus{CPU: 1}); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["node"]; ok {
		t.Fatal("a status report without health sent a node field")
	}
}
