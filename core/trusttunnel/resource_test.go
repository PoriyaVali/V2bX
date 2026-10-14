package trusttunnel

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMetricsPollingReusesLoopbackConnection(t *testing.T) {
	var opened atomic.Int32
	metrics := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"u":{"uplink":123,"downlink":456}}`))
	}))
	metrics.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	metrics.Start()
	defer metrics.Close()
	n := &node{metricsPort: metrics.Listener.Addr().(*net.TCPAddr).Port}
	for i := 0; i < 6; i++ {
		got, err := n.drain(false)
		if err != nil || got["u"].Uplink != 123 || got["u"].Downlink != 456 {
			t.Fatalf("poll %d: got %v, %v", i, got, err)
		}
	}
	if got := opened.Load(); got != 1 {
		t.Fatalf("six sequential polls opened %d connections; want one reused loopback connection", got)
	}
}

func TestConcurrentCredentialWritesStayComplete(t *testing.T) {
	n := &node{dir: t.TempDir(), users: make(map[string]string)}
	for i := 0; i < 128; i++ {
		name := strings.Repeat("x", i+1)
		n.users[name] = name
	}
	start := make(chan struct{})
	errs := make(chan error, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- n.writeCredentials()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent credential sync: %v", err)
		}
	}
	got, err := os.ReadFile(filepath.Join(n.dir, "credentials.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(got), "[[client]]"); count != len(n.users) {
		t.Fatalf("credentials file has %d users, want %d", count, len(n.users))
	}
}
