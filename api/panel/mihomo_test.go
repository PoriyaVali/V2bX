package panel

import (
	"fmt"
	"github.com/PoriyaVali/V2bX/conf"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManagedMihomoNodeContract(t *testing.T) {
	for _, protocol := range []string{"http", "socks5", "mieru", "shadowquic"} {
		t.Run(protocol, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("node_type") != protocol {
					t.Error("wrong protocol namespace")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"server_port":2443,"host":"node.example.test","username":"{{uuid}}","password":"{{uuid}}","tls":true,"transport":"UDP","quic_versions":["v1"],"cwnd":32,"base_config":{"push_interval":60,"pull_interval":90}}`)
			}))
			defer srv.Close()
			c, e := New(&conf.ApiConfig{APIHost: srv.URL, Key: "test-only", NodeType: protocol, NodeID: 1, Timeout: 2})
			if e != nil {
				t.Fatal(e)
			}
			n, e := c.GetNodeInfo()
			if e != nil {
				t.Fatal(e)
			}
			if n.Type != protocol || n.Common.ServerPort != 2443 || n.Mihomo == nil || n.Mihomo.Username != "{{uuid}}" || n.PushInterval != 60*time.Second || n.PullInterval != 90*time.Second {
				t.Fatalf("invalid parsed contract: %+v", n)
			}
			if n.Security != Tls || n.Mihomo.CWND != 32 || n.Mihomo.Transport != "UDP" {
				t.Fatal(n.Mihomo)
			}
		})
	}
}
