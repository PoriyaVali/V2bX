package sing

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

// Nodes whose transport settings a PHP panel emptied, decoded by the panel
// client as V2bX does and started on this core. An emptied Host header came
// as "headers":[], which sing-box's WebSocket settings refused, and the node
// never came up.
func TestSingStartsNodesWithSettingsAsPHPPanelsSendThem(t *testing.T) {
	for _, tc := range []struct{ nodeType, network, settings string }{
		{"vmess", "ws", `{"path":"/ws","headers":[]}`},
		{"vless", "ws", `{"path":"/ws?ed=2048","headers":[]}`},
		{"vless", "httpupgrade", `{"path":"/up","host":"","headers":[]}`},
		{"vmess", "tcp", `{"header":{"type":"none","request":[],"response":[]}}`},
		{"vmess", "grpc", `[]`},
		{"trojan", "ws", `{"path":"/t","headers":[]}`},
	} {
		t.Run(tc.nodeType+"/"+tc.network, func(t *testing.T) {
			port := freeTCPPort(t)
			body := fmt.Sprintf(`{"server_port":%d,"network":%q,"networkSettings":%s,"tls":0,"server_name":"t.example","base_config":{"push_interval":60,"pull_interval":60}}`,
				port, tc.network, tc.settings)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			client, err := panel.New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "k", NodeType: tc.nodeType, Timeout: 5})
			if err != nil {
				t.Fatal(err)
			}
			info, err := client.GetNodeInfo()
			if err != nil {
				t.Fatal(err)
			}
			if tc.nodeType == "trojan" {
				// Trojan is TLS on this core; the certificate is not what is tested.
				info.Security = panel.None
			}
			b, _ := startSing(t)
			opts := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}
			opts.SingOptions.DecoySite = new(false)
			if err := b.AddNode("php-"+tc.nodeType+"-"+tc.network, info, opts); err != nil {
				t.Fatalf("the node did not start: %v", err)
			}
		})
	}
}
