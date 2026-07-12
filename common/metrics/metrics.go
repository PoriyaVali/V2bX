// Package metrics exposes a lightweight Prometheus-text metrics endpoint for
// V2bX, driven by the shared limiter state. No external dependency.
package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PoriyaVali/V2bX/limiter"
	log "github.com/sirupsen/logrus"
)

var startOnce sync.Once

// Start launches an HTTP endpoint serving GET /metrics (Prometheus text format)
// at addr (e.g. ":11111" or "127.0.0.1:11111"). It is a no-op when addr is
// empty, and only starts once.
func Start(addr string) {
	if addr == "" {
		return
	}
	startOnce.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", handleMetrics)
		srv := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.WithField("addr", addr).Info("Metrics endpoint listening on /metrics")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.WithField("err", err).Error("Metrics server stopped")
			}
		}()
	})
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	stats := limiter.Snapshot()
	var b strings.Builder

	b.WriteString("# TYPE v2bx_nodes gauge\n")
	fmt.Fprintf(&b, "v2bx_nodes %d\n", len(stats))

	b.WriteString("# HELP v2bx_node_users Users configured on a node.\n# TYPE v2bx_node_users gauge\n")
	for _, s := range stats {
		fmt.Fprintf(&b, "v2bx_node_users{node=\"%s\"} %d\n", escapeLabel(s.Tag), s.Users)
	}
	b.WriteString("# HELP v2bx_node_online_ips Online device IPs seen since the last report.\n# TYPE v2bx_node_online_ips gauge\n")
	for _, s := range stats {
		fmt.Fprintf(&b, "v2bx_node_online_ips{node=\"%s\"} %d\n", escapeLabel(s.Tag), s.OnlineIPs)
	}
	b.WriteString("# HELP v2bx_node_checks_total Connection limit checks.\n# TYPE v2bx_node_checks_total counter\n")
	for _, s := range stats {
		fmt.Fprintf(&b, "v2bx_node_checks_total{node=\"%s\"} %d\n", escapeLabel(s.Tag), s.Checks)
	}
	b.WriteString("# HELP v2bx_node_rejects_total Connections rejected by the device/ip limit.\n# TYPE v2bx_node_rejects_total counter\n")
	for _, s := range stats {
		fmt.Fprintf(&b, "v2bx_node_rejects_total{node=\"%s\"} %d\n", escapeLabel(s.Tag), s.Rejects)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
