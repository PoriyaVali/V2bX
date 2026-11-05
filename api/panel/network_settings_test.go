package panel

import (
	"encoding/json"
	"testing"
)

func TestNormalizeNetworkSettingsPutsPHPEmptyArraysRight(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// Empty settings, as PHP writes them, are none.
		{`[]`, ``},
		{` [ ] `, ``},
		{`null`, ``},
		{``, ``},
		// An emptied WebSocket or HTTPUpgrade Host header.
		{`{"path":"/ws","headers":[]}`, `{"path":"/ws"}`},
		// tcp's HTTP header with an emptied request.
		{`{"header":{"type":"http","request":{"path":["/"],"headers":[]},"response":[]}}`, `{"header":{"request":{"path":["/"]},"type":"http"}}`},
		{`{"header":[],"seed":null}`, `{"seed":null}`},
		// XHTTP: an empty extra still means the settings are extra's.
		{`{"path":"/","extra":[]}`, `{"extra":{},"path":"/"}`},
		{`{"path":"/","headers":[],"xmux":[],"downloadSettings":[]}`, `{"path":"/"}`},
		{`{"extra":{"headers":[],"xmux":{"maxConcurrency":"4-8"}}}`, `{"extra":{"xmux":{"maxConcurrency":"4-8"}}}`},
		{`{"extra":{"downloadSettings":{"address":"a","port":443,"tlsSettings":[],"xhttpSettings":{"path":"/d","headers":[],"extra":[]}}}}`,
			`{"extra":{"downloadSettings":{"address":"a","port":443,"xhttpSettings":{"extra":{},"path":"/d"}}}}`},
		// Lists stay lists, and numbers keep their digits.
		{`{"extra":{"headers":[],"downloadSettings":{"tlsSettings":{"alpn":[]},"port":12345678901234567890}}}`,
			`{"extra":{"downloadSettings":{"port":12345678901234567890,"tlsSettings":{"alpn":[]}}}}`},
	} {
		if got := string(NormalizeNetworkSettings(json.RawMessage(tc.in))); got != tc.want {
			t.Errorf("NormalizeNetworkSettings(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
	// Nothing to put right, or nothing that decodes: returned as given.
	for _, in := range []string{`{"path":"/","headers":{"Host":"a"}}`, `{"path":`, `"x"`} {
		if got := string(NormalizeNetworkSettings(json.RawMessage(in))); got != in {
			t.Errorf("NormalizeNetworkSettings(%s) = %s, want it unchanged", in, got)
		}
	}
}

// What the cores are given, for settings as a PHP panel sends them.
func TestGetNodeInfo_NetworkSettingsAsPHPPanelsSendThem(t *testing.T) {
	base := `"server_port":443,"base_config":{"push_interval":60,"pull_interval":60}`
	for _, tc := range []struct{ nodeType, body, want string }{
		{"vmess", `{"network":"ws","tls":0,"networkSettings":{"path":"/ws","headers":[]},` + base + `}`, `{"path":"/ws"}`},
		{"vmess", `{"network":"kcp","tls":0,"networkSettings":null,` + base + `}`, ``},
		{"vless", `{"network":"xhttp","tls":0,"networkSettings":{"path":"/xh","extra":[]},` + base + `}`, `{"extra":{},"path":"/xh"}`},
		{"vless", `{"network":"tcp","tls":0,"network_settings":[],` + base + `}`, ``},
	} {
		n, err := fetchNode(t, tc.nodeType, tc.body)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.nodeType, tc.body, err)
		}
		if got := string(n.VAllss.NetworkSettings); got != tc.want {
			t.Errorf("%s %s: settings %s, want %s", tc.nodeType, tc.body, got, tc.want)
		}
	}
	n, err := fetchNode(t, "trojan", `{"network":"ws","server_name":"t.example","networkSettings":{"path":"/t","headers":[]},`+base+`}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(n.Trojan.NetworkSettings); got != `{"path":"/t"}` {
		t.Errorf("trojan settings %s", got)
	}
}
