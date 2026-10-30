package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

func TestMihomoSetupCoreSelection(t *testing.T) {
	for _, protocol := range []string{"http", "socks5", "mieru", "shadowquic", "sudoku", "snell"} {
		info := &panel.NodeInfo{Type: protocol}
		if got := resolveSetupCore("auto", info); got != "mihomo" {
			t.Fatalf("%s selected %s", protocol, got)
		}
		if e := validateSetupCore("mihomo", info); e != nil {
			t.Fatal(e)
		}
	}
	for _, protocol := range []string{"wireguard", "ssh", "ssr", "gostrelay", "masque", "openvpn", "tailscale", "zerotier", "easytier"} {
		if setupCoreSupports("mihomo", protocol) {
			t.Fatalf("client-only protocol %s advertised as a managed server", protocol)
		}
	}
}

// IDs are local to each protocol's table: the first Mieru node shares ID 1
// with the first SOCKS5 and HTTP nodes. Those being an external service (501)
// or a child node (409) must not stop the wizard from finding the Mieru node.
func TestGuidedFindsMieruBesideNodesThePanelDeclines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("node_id") == "1" {
			switch r.URL.Query().Get("node_type") {
			case "mieru":
				fmt.Fprint(w, `{"server_port":2999,"host":"node.example.test","transport":"TCP","base_config":{"push_interval":60,"pull_interval":60}}`)
				return
			case "socks5":
				w.WriteHeader(http.StatusNotImplemented)
				fmt.Fprint(w, `{"message":"external service"}`)
				return
			case "http":
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"message":"child node"}`)
				return
			}
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"message":"server is not exist"}`)
	}))
	defer srv.Close()
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	output := filepath.Join(t.TempDir(), "config.json")
	text, err := executeGuidedTest(srv.URL, output, "none\n\n\nn\n1\n6\n\nn\n")
	if err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	parsed := conf.New()
	if err := parsed.LoadFromPath(output); err != nil {
		t.Fatal(err)
	}
	if len(parsed.NodeConfig) != 1 {
		t.Fatalf("nodes=%d: %s", len(parsed.NodeConfig), text)
	}
	node := parsed.NodeConfig[0]
	if node.Options.Core != "mihomo" || node.ApiConfig.NodeType != "mieru" || node.ApiConfig.NodeID != 1 || !strings.Contains(text, "mieru:1") {
		t.Fatalf("detected %s:%d on %s: %s", node.ApiConfig.NodeType, node.ApiConfig.NodeID, node.Options.Core, text)
	}
}

// A Mieru node looked up on another core is not found there: the wizard names
// the core that serves it.
func TestGuidedNamesTheCoreOfANodeOnAnotherCore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("node_id") == "1" && r.URL.Query().Get("node_type") == "mieru" {
			fmt.Fprint(w, `{"server_port":2999,"transport":"TCP"}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"message":"server is not exist"}`)
	}))
	defer srv.Close()
	t.Setenv("V2BX_TEST_API_KEY", "guided-key")
	output := filepath.Join(t.TempDir(), "config.json")
	text, err := executeGuidedTest(srv.URL, output, "none\n\n\nn\n1\n1\nn\n")
	if err == nil {
		t.Fatalf("a Mieru node was configured on sing-box: %s", text)
	}
	if !strings.Contains(text, "ID 1 is a mieru node: choose core 6 (mihomo)") {
		t.Fatalf("the wizard did not name the Mihomo core: %s", text)
	}
}
