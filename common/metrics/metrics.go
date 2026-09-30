// Package metrics exposes a lightweight Prometheus-text metrics endpoint for
// V2bX, driven by the shared limiter state. No external dependency.
package metrics

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PoriyaVali/V2bX/common/memguard"
	"github.com/PoriyaVali/V2bX/limiter"
	log "github.com/sirupsen/logrus"
)

var (
	serverMu sync.Mutex
	server   *http.Server
	listen   string
)

// Start applies the desired metrics address. Calling it again moves, enables or
// disables the endpoint, which makes Metrics.Listen obey config hot reloads.
func Start(addr string) error {
	serverMu.Lock()
	defer serverMu.Unlock()
	if addr == listen && (addr == "" || server != nil) {
		return nil
	}
	if server != nil {
		if err := server.Close(); err != nil {
			return fmt.Errorf("close metrics server: %w", err)
		}
		server = nil
		listen = ""
	}
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen for metrics on %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", handleMetrics)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	server, listen = srv, addr
	go func() {
		log.WithField("addr", addr).Info("Metrics endpoint listening on /metrics")
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.WithField("err", err).Error("Metrics server stopped")
		}
	}()
	return nil
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

	writeProcessMetrics(&b)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// writeProcessMetrics adds the process and machine readings memguard takes, so
// memory, goroutines and open files can be graphed against uptime.
func writeProcessMetrics(b *strings.Builder) {
	s := memguard.Read()
	gauge := func(name, help string, v uint64) {
		fmt.Fprintln(b, "# HELP", name, help)
		fmt.Fprintln(b, "# TYPE", name, "gauge")
		fmt.Fprintln(b, name, v)
	}
	gauge("v2bx_process_rss_bytes", "Resident memory of the V2bX process.", s.RSSBytes)
	gauge("v2bx_process_heap_inuse_bytes", "Go heap in use.", s.HeapInuseBytes)
	gauge("v2bx_process_goroutines", "Goroutines.", uint64(s.Goroutines))
	gauge("v2bx_process_open_files", "Open file descriptors, sockets included.", uint64(s.OpenFiles))
	gauge("v2bx_memory_soft_limit_bytes", "Go soft memory limit; 0 = none.", s.SoftLimitBytes)
	gauge("v2bx_machine_ram_ceiling_bytes", "RAM available to the process: cgroup limit or MemTotal.", s.CeilingBytes)
	gauge("v2bx_machine_ram_available_bytes", "MemAvailable, or cgroup headroom when tighter.", s.AvailableBytes)
}
