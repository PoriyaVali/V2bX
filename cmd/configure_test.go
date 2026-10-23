package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
)

func setupPanel(t *testing.T) *httptest.Server {
	t.Helper()
	bodies := map[string]string{
		"vless:1":       `{"tls":2,"network":"tcp","tls_settings":{"server_name":"borrowed.example.test"}}`,
		"vless:2":       `{"tls":1,"network":"tcp","tls_settings":{"server_name":"tls.example.test"}}`,
		"hysteria2:3":   `{"version":2,"host":"node.example.test","server_name":"hy.example.test"}`,
		"mdns:4":        `{"domain":["dns.example.test"]}`,
		"tuic:5":        `{"host":"tuic.example.test"}`,
		"vmess:6":       `{"tls":0,"network":"ws"}`,
		"trojan:7":      `{"server_name":"trojan.example.test"}`,
		"trusttunnel:8": `{"hostname":"tt.example.test","cert_type":"letsencrypt","acme_email":"admin@example.test"}`,
		"anytls:9":      `{"tls":1,"server_name":"any.example.test"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		body, ok := bodies[q.Get("node_type")+":"+q.Get("node_id")]
		if !ok {
			http.Error(w, "unknown node", 404)
			return
		}
		if q.Get("token") == "" {
			t.Error("missing API key")
		}
		var value map[string]any
		_ = json.Unmarshal([]byte(body), &value)
		value["server_port"] = 2443
		value["base_config"] = map[string]int{"push_interval": 60, "pull_interval": 60}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConfigureInfersMixedCoresAndCertificatesFromPanel(t *testing.T) {
	srv := setupPanel(t)
	path := filepath.Join(t.TempDir(), "config.json")
	key := "fictional-key-\"\\&?=not-shell-$(id)"
	t.Setenv("V2BX_TEST_API_KEY", key)
	c := newConfigureCommand()
	c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", "vless:1,vless:2,hysteria2:3,mdns:4,tuic:5,vmess:6,trojan:7,trusttunnel:8,anytls:9", "--output", path})
	var output bytes.Buffer
	c.SetOut(&output)
	c.SetErr(&output)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), key) {
		t.Fatal("wizard printed the API secret")
	}
	parsed := conf.New()
	if err := parsed.LoadFromPath(path); err != nil {
		t.Fatal(err)
	}
	if len(parsed.CoresConfig) != 4 || len(parsed.NodeConfig) != 9 {
		t.Fatalf("unexpected core/node count: %d/%d", len(parsed.CoresConfig), len(parsed.NodeConfig))
	}
	wantDomains := map[int]string{2: "tls.example.test", 3: "hy.example.test", 5: "tuic.example.test", 7: "trojan.example.test", 9: "any.example.test"}
	for _, n := range parsed.NodeConfig {
		if n.ApiConfig.Key != key {
			t.Fatal("credential lost in JSON escaping")
		}
		cert := n.Options.CertConfig
		if domain := wantDomains[n.ApiConfig.NodeID]; domain != "" {
			if cert.CertMode != "http" || cert.CertDomain != domain || !filepath.IsAbs(cert.KeyFile) {
				t.Fatalf("node %d cert: %+v", n.ApiConfig.NodeID, cert)
			}
		} else if cert.CertMode != "none" {
			t.Fatalf("unnecessary ACME for node %d", n.ApiConfig.NodeID)
		}
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("config containing credentials is not private")
		}
	}
}

func TestInteractiveConfigureNeedsOnlyPanelKeyAndNodeList(t *testing.T) {
	srv := setupPanel(t)
	path := filepath.Join(t.TempDir(), "config.json")
	c := newConfigureCommand()
	c.SetArgs([]string{"--output", path})
	c.SetIn(strings.NewReader(srv.URL + "\nsecret-api-key\nvless:2,hysteria2:3,mdns:4\n"))
	var output bytes.Buffer
	c.SetOut(&output)
	c.SetErr(&output)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "TLS domain for") || strings.Contains(output.String(), "secret-api-key") {
		t.Fatalf("unnecessary prompt or secret echo: %s", output.String())
	}
}

func TestConfigureFailurePreservesExistingConfiguration(t *testing.T) {
	srv := setupPanel(t)
	for _, nodes := range []string{"vless:2,mdns:999", "vless:2,vless:2", "vless:0", "not-a-node"} {
		t.Run(nodes, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte("operator config"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("V2BX_TEST_API_KEY", "test-secret")
			c := newConfigureCommand()
			c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", nodes, "--output", path})
			var output bytes.Buffer
			c.SetOut(&output)
			c.SetErr(&output)
			if err := c.Execute(); err == nil {
				t.Fatal("invalid setup accepted")
			}
			data, _ := os.ReadFile(path)
			if string(data) != "operator config" {
				t.Fatal("failed setup overwrote active config")
			}
		})
	}
}

func TestConfigureBackupIsPrivateAndDNSSecretsAreNotPrinted(t *testing.T) {
	srv := setupPanel(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("old private config"), 0644); err != nil {
		t.Fatal(err)
	}
	dnsPath := filepath.Join(dir, "dns.json")
	if err := os.WriteFile(dnsPath, []byte(`{"CLOUDFLARE_DNS_API_TOKEN":"fictional-dns-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("V2BX_TEST_API_KEY", "fictional-api-secret")
	c := newConfigureCommand()
	c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", "vless:2", "--output", path, "--dns-provider", "cloudflare", "--dns-env-file", dnsPath})
	var output bytes.Buffer
	c.SetOut(&output)
	c.SetErr(&output)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "fictional-dns-secret") || strings.Contains(output.String(), "fictional-api-secret") {
		t.Fatal("secret in setup output")
	}
	parsed := conf.New()
	if err := parsed.LoadFromPath(path); err != nil {
		t.Fatal(err)
	}
	cert := parsed.NodeConfig[0].Options.CertConfig
	if cert.CertMode != "dns" || cert.Provider != "cloudflare" || cert.DNSEnv["CLOUDFLARE_DNS_API_TOKEN"] != "fictional-dns-secret" {
		t.Fatal("DNS configuration lost")
	}
	backup, _ := os.ReadFile(path + ".bak")
	if string(backup) != "old private config" {
		t.Fatal("old config was not backed up")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path + ".bak")
		if info.Mode().Perm() != 0600 {
			t.Fatal("backup exposes credentials")
		}
	}
}

func TestConfigureRejectsIncompleteFirstPanelResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotModified} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer srv.Close()
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte("keep active config"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("V2BX_TEST_API_KEY", "test-secret")
			c := newConfigureCommand()
			c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", "vless:1", "--output", path})
			var output bytes.Buffer
			c.SetOut(&output)
			c.SetErr(&output)
			if err := c.Execute(); err == nil {
				t.Fatal("incomplete configuration accepted")
			}
			data, _ := os.ReadFile(path)
			if string(data) != "keep active config" {
				t.Fatal("incomplete response replaced active configuration")
			}
		})
	}
}

func TestConfigureSelectsFallbackCoreAndPreservesCoverOptions(t *testing.T) {
	srv := setupPanel(t)
	directory := t.TempDir()
	root := filepath.Join(directory, "public")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>Owner site</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("V2BX_TEST_API_KEY", "test-secret")
	output := filepath.Join(directory, "config.json")
	c := newConfigureCommand()
	c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", "vless:1,vless:2,hysteria2:3,trojan:7", "--cover-root", root, "--cover-title", "Owner Notes", "--cover-tcp=false", "--output", output})
	var logs bytes.Buffer
	c.SetOut(&logs)
	c.SetErr(&logs)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	parsed := conf.New()
	if err := parsed.LoadFromPath(output); err != nil {
		t.Fatal(err)
	}
	want := map[int]string{1: "sing", 2: "xray", 3: "sing", 7: "xray"}
	for _, node := range parsed.NodeConfig {
		if node.Options.Core != want[node.ApiConfig.NodeID] {
			t.Fatalf("node %d selected %s", node.ApiConfig.NodeID, node.Options.Core)
		}
		cover := node.Options.Decoy
		if cover == nil || cover.Root != root || cover.Title != "Owner Notes" || cover.TCPEnabled() {
			t.Fatal("cover configuration did not survive runtime parsing")
		}
	}
}
