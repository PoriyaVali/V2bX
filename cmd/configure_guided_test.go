package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

func TestVLESSEncryptionRequiresCompatibleCore(t *testing.T) {
	info := &panel.NodeInfo{Type: "vless", Security: panel.Reality, VAllss: &panel.VAllssNode{Network: "tcp", Encryption: "mlkem768x25519plus"}}
	if err := validateSetupCore("sing", info); err == nil || !strings.Contains(err.Error(), "Xray") {
		t.Fatal("wizard accepted encrypted VLESS on a core that cannot serve it")
	}
	if err := validateSetupCore("xray", info); err != nil || resolveSetupCore("auto", info) != "xray" {
		t.Fatal("automatic setup did not use the compatible encryption core")
	}
}

func executeGuidedTest(panelURL, output, input string) (string, error) {
	c := newConfigureCommand()
	c.SetArgs([]string{"--guided", "--panel", panelURL, "--api-key-env", "V2BX_TEST_API_KEY", "--output", output})
	c.SetIn(strings.NewReader(input))
	var text bytes.Buffer
	c.SetOut(&text)
	c.SetErr(&text)
	err := c.Execute()
	return text.String(), err
}

func TestGuidedHonorsBothCoresForHysteriaVLESSAndVMess(t *testing.T) {
	srv := setupPanel(t)
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	for _, row := range []struct {
		id, choice, core string
	}{{"3", "1", "sing"}, {"3", "3", "hysteria2"}, {"2", "1", "sing"}, {"2", "2", "xray"}, {"6", "1", "sing"}, {"6", "2", "xray"}} {
		t.Run(row.id+"-"+row.core, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "config.json")
			// Countries, operational log, core log and mux stay manual. Once
			// ID/core are entered, one Enter approves the detected TLS/domain.
			text, err := executeGuidedTest(srv.URL, output, "none\n\n\ny\n"+row.id+"\n"+row.choice+"\n\nn\n")
			if err != nil {
				t.Fatalf("%v: %s", err, text)
			}
			parsed := conf.New()
			if err := parsed.LoadFromPath(output); err != nil {
				t.Fatal(err)
			}
			node := parsed.NodeConfig[0]
			if node.Options.Core != row.core {
				t.Fatalf("chosen core %s replaced by %s", row.core, node.Options.Core)
			}
			if row.core == "sing" && row.id != "3" && !node.Options.SingOptions.Multiplex.Enabled {
				t.Fatal("manual mux choice was discarded")
			}
			if row.core == "xray" && parsed.CoresConfig[0].XrayConfig.LogConfig.Level != "warning" {
				t.Fatal("wizard emitted an invalid Xray warn level")
			}
		})
	}
}

func TestGuidedAnyTLSHostWithDifferentSNIAndReality(t *testing.T) {
	srv := setupPanel(t)
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	for _, id := range []string{"9", "57"} {
		t.Run(id, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "config.json")
			text, err := executeGuidedTest(srv.URL, output, "none\n\n\ny\n"+id+"\n1\n\nn\n")
			if err != nil {
				t.Fatalf("%v: %s", err, text)
			}
			parsed := conf.New()
			if err := parsed.LoadFromPath(output); err != nil {
				t.Fatal(err)
			}
			n := parsed.NodeConfig[0]
			if n.ApiConfig.NodeType != "anytls" || n.Options.Core != "sing" || n.Options.SingOptions.Multiplex.Enabled {
				t.Fatal("AnyTLS protocol/core/mux was misidentified")
			}
			if id == "9" && (n.Options.CertConfig.CertDomain != "any.example.test" || n.Options.CertConfig.CertMode != "http") {
				t.Fatal("AnyTLS host was not used for the certificate")
			}
			if id == "57" && (n.Options.CertConfig.CertMode != "none" || !strings.Contains(text, "REALITY; no certificate")) {
				t.Fatal("AnyTLS REALITY incorrectly requested a certificate")
			}
			if strings.Contains(text, "Panel has no certificate hostname") || strings.Contains(text, "Node type |") {
				t.Fatal("recognized AnyTLS still needs manual type/domain input")
			}
		})
	}
}

func TestGuidedDuplicateProtocolIDsRequireAnExplicitChoice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node_type") == "anytls" {
			fmt.Fprint(w, `{"server_port":443,"tls":2}`)
		} else if r.URL.Query().Get("node_type") == "vless" {
			fmt.Fprint(w, `{"server_port":8443,"tls":0,"network":"tcp"}`)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	output := filepath.Join(t.TempDir(), "config.json")
	// Empty input at the ambiguous type prompt must not pick AnyTLS. The
	// following explicit "2" selects VLESS; the next Enter confirms it.
	text, err := executeGuidedTest(srv.URL, output, "none\n\n\nn\n57\n1\n\n2\n\nn\n")
	if err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	parsed := conf.New()
	if err := parsed.LoadFromPath(output); err != nil {
		t.Fatal(err)
	}
	if parsed.NodeConfig[0].ApiConfig.NodeType != "vless" || !strings.Contains(text, "Choose 1–2") {
		t.Fatal("an ambiguous ID silently selected the first protocol")
	}
}

func TestGuidedCancellationAndEOFKeepExistingConfiguration(t *testing.T) {
	srv := setupPanel(t)
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	for _, ending := range []string{"n\n", "", "\n"} {
		t.Run(fmt.Sprintf("ending-%q", ending), func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "config.json")
			original := []byte("operator configuration")
			if err := os.WriteFile(output, original, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := executeGuidedTest(srv.URL, output, "none\n\n\nn\n9\n1\n"+ending)
			if err == nil {
				t.Fatal("cancelled or incomplete wizard saved a configuration")
			}
			actual, _ := os.ReadFile(output)
			if !bytes.Equal(actual, original) {
				t.Fatal("cancelled wizard overwrote operator configuration")
			}
			if _, err := os.Stat(output + ".bak"); !os.IsNotExist(err) {
				t.Fatal("cancelled wizard touched the backup")
			}
		})
	}
}

func TestGuidedRetainsExistingDNSCertificateAndCredentials(t *testing.T) {
	srv := setupPanel(t)
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	output := filepath.Join(t.TempDir(), "config.json")
	cert := conf.CertConfig{CertMode: "dns", CertDomain: "any.example.test", Provider: "cloudflare", Email: "owner@example.test", CertFile: "/owned/live.pem", KeyFile: "/owned/live.key", AccountDir: "/owned/accounts", DNSEnv: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "private-dns-value"}}
	original, err := json.Marshal(map[string]any{"Nodes": []map[string]any{{"ApiHost": srv.URL, "NodeType": "anytls", "NodeID": 9, "CertConfig": cert}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, original, 0600); err != nil {
		t.Fatal(err)
	}
	// Edit only the listener, accepting the existing DNS certificate defaults.
	input := strings.Join([]string{"none", "", "", "n", "9", "1", "e", "0.0.0.0", "", "", "", "", "", "n", ""}, "\n")
	text, err := executeGuidedTest(srv.URL, output, input)
	if err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	parsed := conf.New()
	if err := parsed.LoadFromPath(output); err != nil {
		t.Fatal(err)
	}
	actual := parsed.NodeConfig[0].Options.CertConfig
	if parsed.NodeConfig[0].Options.ListenIP != "0.0.0.0" {
		t.Fatal("listener edit was not saved")
	}
	if actual.CertMode != "dns" || actual.CertFile != cert.CertFile || actual.KeyFile != cert.KeyFile || actual.AccountDir != cert.AccountDir || actual.DNSEnv["CLOUDFLARE_DNS_API_TOKEN"] != "private-dns-value" {
		t.Fatal("existing certificate paths, renewal mode or credentials changed")
	}
	if strings.Contains(text, "private-dns-value") || strings.Contains(text, "guided-key") {
		t.Fatal("wizard printed a credential")
	}
	backup, _ := os.ReadFile(output + ".bak")
	if !bytes.Equal(backup, original) {
		t.Fatal("previous configuration was not backed up exactly")
	}
}

func TestGuidedCanRetryWrongIDWithoutRepeatingPanelOrPreferences(t *testing.T) {
	srv := setupPanel(t)
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	output := filepath.Join(t.TempDir(), "config.json")
	text, err := executeGuidedTest(srv.URL, output, "none\n\n\nn\n999\n1\n\n9\n1\n\nn\n")
	if err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	parsed := conf.New()
	if err := parsed.LoadFromPath(output); err != nil {
		t.Fatal(err)
	}
	if len(parsed.NodeConfig) != 1 || parsed.NodeConfig[0].ApiConfig.NodeID != 9 || strings.Count(text, "Enable multiplexing (smux)") != 1 {
		t.Fatal("retry duplicated nodes or discarded global input")
	}
}

func TestConfigureUnattendedPerNodeCoreOverrides(t *testing.T) {
	srv := setupPanel(t)
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	output := filepath.Join(t.TempDir(), "config.json")
	c := newConfigureCommand()
	c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", "vless:2,hysteria2:3,vmess:6", "--node-cores", "vless:2=sing,hysteria2:3=hysteria2,vmess:6=xray", "--output", output})
	var text bytes.Buffer
	c.SetOut(&text)
	c.SetErr(&text)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	parsed := conf.New()
	if err := parsed.LoadFromPath(output); err != nil {
		t.Fatal(err)
	}
	for _, n := range parsed.NodeConfig {
		want := map[int]string{2: "sing", 3: "hysteria2", 6: "xray"}[n.ApiConfig.NodeID]
		if n.Options.Core != want {
			t.Fatalf("node %d core %s; want %s", n.ApiConfig.NodeID, n.Options.Core, want)
		}
	}
}

func TestConfigureRejectsIncompatibleAndUnusedCoreOverrides(t *testing.T) {
	srv := setupPanel(t)
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	for _, override := range []string{"anytls:9=xray", "anytls:9=hysteria2", "vless:999=sing"} {
		t.Run(override, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "config.json")
			original := []byte("keep operator config")
			if err := os.WriteFile(output, original, 0600); err != nil {
				t.Fatal(err)
			}
			c := newConfigureCommand()
			c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", "anytls:9", "--node-cores", override, "--output", output})
			var text bytes.Buffer
			c.SetOut(&text)
			c.SetErr(&text)
			if err := c.Execute(); err == nil {
				t.Fatal("invalid core override accepted")
			}
			actual, _ := os.ReadFile(output)
			if !bytes.Equal(actual, original) {
				t.Fatal("invalid core override replaced the configuration")
			}
		})
	}
}
