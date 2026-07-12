package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/limiter"
)

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
