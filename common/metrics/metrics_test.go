package metrics

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/limiter"
)

func TestStartCanMoveAndDisableEndpoint(t *testing.T) {
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserve.Addr().String()
	reserve.Close()
	if err := Start(addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Start("") })
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("metrics endpoint did not start: %v", err)
	}
	resp.Body.Close()
	if err := Start(""); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get("http://" + addr + "/metrics"); err == nil {
		t.Fatal("metrics endpoint remained reachable after it was disabled")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	limiter.Init()
	tag := "metrics-node"
	users := []panel.UserInfo{{Id: 1, Uuid: "u1", DeviceLimit: 1}}
	l := limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{1: 5}) // alive over limit
	taguuid := format.UserTag(tag, "u1")
	l.CheckLimit(taguuid, "1.1.1.1", true, true) // over device limit -> reject

	rec := httptest.NewRecorder()
	handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"v2bx_nodes 1",
		`v2bx_node_users{node="metrics-node"} 1`,
		`v2bx_node_checks_total{node="metrics-node"} 1`,
		`v2bx_node_rejects_total{node="metrics-node"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q\n---\n%s", want, body)
		}
	}
}
