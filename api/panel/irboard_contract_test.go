package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/serverstatus"
	"github.com/PoriyaVali/V2bX/conf"
)

// Generated through Irboard's real HTTP routes and install.sql, not copied
// example JSON. See testdata/irboard/README.md to regenerate both sides.
type irboardResponse struct {
	Body        []byte `json:"body"`
	ContentType string `json:"content_type"`
	ETag        string `json:"etag"`
}

func TestIrboardGeneratedContract(t *testing.T) {
	var fixtures struct {
		Configs   map[string]irboardResponse `json:"configs"`
		Responses map[string]irboardResponse `json:"responses"`
	}
	data, err := os.ReadFile("testdata/irboard/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for typ, fixture := range fixtures.Configs {
		t.Run("config/"+typ, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("token") != "contract-token" {
					t.Error("token missing")
				}
				if etag := r.Header.Get("If-None-Match"); etag != "" && etag == fixture.ETag {
					w.WriteHeader(304)
					return
				}
				w.Header().Set("Content-Type", fixture.ContentType)
				w.Header().Set("ETag", fixture.ETag)
				_, _ = w.Write(fixture.Body)
			}))
			defer srv.Close()
			c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: typ, Key: "contract-token"})
			if err != nil {
				t.Fatal(err)
			}
			info, err := c.GetNodeInfo()
			if err != nil {
				t.Fatal(err)
			}
			if info == nil || info.Common.ServerPort != 2443 || info.PushInterval != 41*time.Second || info.PullInterval != 31*time.Second || info.NodeReportMinTraffic != 7 || info.DeviceOnlineMinTraffic != 3 {
				t.Fatalf("panel settings did not reach node: %+v", info)
			}
			switch typ {
			case "http", "socks5", "mieru", "shadowquic":
				if info.Mihomo == nil || info.Common.Host != "node.example.test" || info.Mihomo.Username != "{{uuid}}" || info.Mihomo.Password != "{{uuid}}" {
					t.Fatal("managed Mihomo node identity or certificate host lost")
				}
				if (typ == "http" || typ == "socks5") && info.Security != Tls {
					t.Fatal("managed TLS flag lost")
				}
			case "vless":
				if info.Security != Reality || info.VAllss.TlsSettings.Xver != 2 || info.VAllss.TlsSettings.ServerPort != "443" {
					t.Fatal("REALITY settings lost")
				}
			case "anytls":
				if info.Security != Reality || info.AnyTls.TlsSettings.Xver != 2 || len(info.AnyTls.PaddingScheme) != 1 {
					t.Fatal("AnyTLS settings lost")
				}
			case "mdns":
				if len(info.Mdns.Domain) != 1 || info.Mdns.NodeSecret == "" || info.Mdns.EncryptionMethod != 2 {
					t.Fatal("MDNS authentication settings lost")
				}
			case "trusttunnel":
				if info.TrustTunnel.Hostname != "cert.example.test" || info.TrustTunnel.HasIPv6 == nil || !*info.TrustTunnel.HasIPv6 {
					t.Fatal("endpoint settings lost")
				}
			case "hysteria2":
				if info.Type != "hysteria2" || info.Hysteria2.ObfsPassword != "fictional-obfs" {
					t.Fatal("Hysteria2 settings lost")
				}
			case "v2ray":
				if info.Type != "vmess" {
					t.Fatal("legacy node alias lost")
				}
			}
			if info, err := c.GetNodeInfo(); err != nil || info != nil {
				t.Fatalf("conditional config: %v / %v", info, err)
			}
		})
	}
	for _, name := range []string{"users_json", "users_msgpack", "users_empty_json", "users_empty_msgpack"} {
		t.Run(name, func(t *testing.T) {
			fixture := fixtures.Responses[name]
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if etag := r.Header.Get("If-None-Match"); etag != "" && etag == fixture.ETag {
					w.WriteHeader(304)
					return
				}
				w.Header().Set("Content-Type", fixture.ContentType)
				w.Header().Set("ETag", fixture.ETag)
				_, _ = w.Write(fixture.Body)
			}))
			defer srv.Close()
			c, _ := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: "mdns", Key: "contract-token"})
			users, err := c.GetUserList()
			if err != nil {
				t.Fatal(err)
			}
			if name == "users_json" || name == "users_msgpack" {
				if len(users) != 1 || users[0] != (UserInfo{Id: 1, Uuid: "11111111-2222-3333-4444-555555555555", SpeedLimit: 23, DeviceLimit: 2}) {
					t.Fatalf("eligible user contract: %+v", users)
				}
			} else if users == nil || len(users) != 0 {
				t.Fatalf("empty list must revoke all users: %+v", users)
			}
			if _, err := c.GetUserList(); !errors.Is(err, ErrUserListNotModified) {
				t.Fatalf("304 lost: %v", err)
			}
		})
	}
	t.Run("alive_and_receipts", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fixture := fixtures.Responses["ack"]
			if r.Method == http.MethodGet {
				fixture = fixtures.Responses["alive_empty"]
			}
			w.Header().Set("Content-Type", fixture.ContentType)
			_, _ = w.Write(fixture.Body)
		}))
		defer srv.Close()
		c, _ := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: "mdns", Key: "contract-token"})
		if alive, err := c.GetUserAlive(); err != nil || alive == nil || len(alive) != 0 {
			t.Fatalf("empty alive object: %v / %v", alive, err)
		}
		if err := c.ReportUserTrafficWithID("contract-batch-0001", []UserTraffic{{UID: 1, Upload: 105, Download: 209}}); err != nil {
			t.Fatal(err)
		}
		online := map[int][]string{1: {}}
		if err := c.ReportNodeOnlineUsers(&online); err != nil {
			t.Fatal(err)
		}
		if err := c.ReportNodeStatus(&serverstatus.SystemStatus{CPU: 1.2}); err != nil {
			t.Fatal(err)
		}
	})
}
