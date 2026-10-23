package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Use the exact tagged release build, including core registration and the real
// file watcher, lifecycle and UDP listener. Enabled in CI after that build.
func TestServerRejectedCoreReloadKeepsDNSNode(t *testing.T) {
	binary := os.Getenv("V2BX_TEST_BINARY")
	if binary == "" {
		t.Skip("set V2BX_TEST_BINARY to the release-tagged binary")
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch filepath.Base(r.URL.Path) {
		case "config":
			fmt.Fprintf(w, `{"server_port":%d,"domain":["t.example.test"],"base_config":{"push_interval":60,"pull_interval":60}}`, port)
		case "user":
			fmt.Fprint(w, `{"users":[]}`)
		case "alivelist":
			fmt.Fprint(w, `{"alive":{}}`)
		default:
			fmt.Fprint(w, `{"data":true}`)
		}
	}))
	defer panel.Close()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	badRoute := filepath.Join(dir, "route.json")
	if err := os.WriteFile(badRoute, []byte(`{broken`), 0600); err != nil {
		t.Fatal(err)
	}
	writeConfig := func(cores []map[string]any) {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"Cores": cores,
			"Nodes": []map[string]any{{"ApiHost": panel.URL, "NodeID": 1, "NodeType": "mdns", "ApiKey": "test-token", "ListenIP": "127.0.0.1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		tmp := configPath + ".tmp"
		if err := os.WriteFile(tmp, body, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, configPath); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig([]map[string]any{{"Type": "mdns"}})
	logPath := filepath.Join(dir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	process := exec.Command(binary, "server", "-c", configPath)
	process.Stdout, process.Stderr = logFile, logFile
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	t.Cleanup(func() {
		_ = process.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server stopped with error: %v", err)
			}
		case <-time.After(10 * time.Second):
			_ = process.Process.Kill()
			<-done
			t.Error("server did not stop cleanly")
		}
	})
	awaitLog := func(marker string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			body, _ := os.ReadFile(logPath)
			if strings.Contains(string(body), marker) {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		body, _ := os.ReadFile(logPath)
		t.Fatalf("server did not reach %q: %s", marker, body)
	}
	probe := func() {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion("t.example.test.", dns.TypeA)
		answer, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil || answer == nil || !answer.Response || answer.Id != q.Id {
			t.Fatalf("live DNS node stopped responding: %v / %v", answer, err)
		}
	}
	awaitLog("Nodes started")
	probe()
	writeConfig([]map[string]any{{"Type": "mdns"}, {"Type": "xray", "RouteConfigPath": badRoute}})
	awaitLog("new core config rejected; keeping the running nodes")
	probe()
	// A corrected save must still be picked up after rejecting the first one.
	writeConfig([]map[string]any{{"Type": "mdns"}, {"Type": "xray"}})
	awaitLog("Nodes restarted")
	probe()
}
