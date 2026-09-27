package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
)

// fetchNode serves body as the panel's config reply and decodes it the way a
// node of nodeType would.
func fetchNode(t *testing.T, nodeType, body string) (*NodeInfo, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "k", NodeType: nodeType, Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	return c.GetNodeInfo()
}

// The panel's REALITY form stores its Proxy Protocol choice as a number. That
// used to fail the whole decode, so the node never came up.
func TestGetNodeInfo_RealityXverNumberOrString(t *testing.T) {
	cases := []struct {
		name, tls string
		xver      uint64
		port      string
	}{
		{"number, as the admin form saves it", `"xver":2,"server_port":"443"`, 2, "443"},
		{"string, as older rows hold it", `"xver":"1","server_port":"443"`, 1, "443"},
		{"absent", `"server_port":"8443"`, 0, "8443"},
		{"null", `"xver":null,"server_port":null`, 0, ""},
		{"port as a number", `"xver":0,"server_port":443`, 0, "443"},
	}
	for _, nodeType := range []string{"vless", "anytls"} {
		for _, c := range cases {
			t.Run(nodeType+"/"+c.name, func(t *testing.T) {
				body := `{"server_port":443,"network":"tcp","tls":2,"padding_scheme":[],
				  "tls_settings":{"server_name":"a.example","dest":"a.example","short_id":"ab",
				  "private_key":"k",` + c.tls + `},"base_config":{"push_interval":60,"pull_interval":60}}`
				n, err := fetchNode(t, nodeType, body)
				if err != nil {
					t.Fatalf("GetNodeInfo: %v", err)
				}
				var ts TlsSettings
				if nodeType == "vless" {
					ts = n.VAllss.TlsSettings
				} else {
					ts = n.AnyTls.TlsSettings
				}
				if ts.Xver != c.xver || ts.ServerPort != c.port {
					t.Fatalf("xver=%d server_port=%q, want %d %q", ts.Xver, ts.ServerPort, c.xver, c.port)
				}
				if ts.ServerName != "a.example" || ts.PrivateKey != "k" || ts.ShortId != "ab" {
					t.Fatalf("the other tls_settings fields were lost: %+v", ts)
				}
				if n.Security != Reality {
					t.Fatalf("security = %d, want REALITY", n.Security)
				}
			})
		}
	}
}

func TestGetNodeInfo_RealityXverRejectsGarbage(t *testing.T) {
	body := `{"server_port":443,"network":"tcp","tls":2,"tls_settings":{"xver":"yes"}}`
	if _, err := fetchNode(t, "vless", body); err == nil || !strings.Contains(err.Error(), "xver") {
		t.Fatalf("err = %v, want one naming xver", err)
	}
}

func TestEncSettings_ServerDecryption(t *testing.T) {
	cases := []struct {
		in   EncSettings
		want string
	}{
		// What the panel stores when the operator only picks the method.
		{EncSettings{PrivateKey: "K"}, "mlkem768x25519plus.native.0s.K"},
		{EncSettings{Rtt: "1rtt", Ticket: "0s", PrivateKey: "K"}, "mlkem768x25519plus.native.0s.K"},
		{EncSettings{Rtt: "0rtt", PrivateKey: "K"}, "mlkem768x25519plus.native.600s.K"},
		{EncSettings{Mode: "xorpub", Rtt: "0rtt", Ticket: "300-600s", ServerPadding: "100-111-1111", PrivateKey: "K"},
			"mlkem768x25519plus.xorpub.300-600s.100-111-1111.K"},
	}
	for _, c := range cases {
		if got := c.in.ServerDecryption(); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.in, got, c.want)
		}
	}
}

// The panel serves hysteria 1 and 2 as one node type and says which in
// "version"; that, not the node's NodeType, decides the protocol served.
func TestGetNodeInfo_HysteriaVersionDecides(t *testing.T) {
	v1 := `{"version":1,"host":"h","server_port":443,"server_name":"s","up_mbps":10,"down_mbps":20,"obfs":"o"}`
	v2 := `{"version":2,"host":"h","server_port":443,"server_name":"s","up_mbps":0,"down_mbps":0,
	  "ignore_client_bandwidth":true,"obfs":"salamander","obfs-password":"p"}`
	noVersion := `{"host":"h","server_port":443,"up_mbps":10,"down_mbps":20}`
	cases := []struct {
		configured, body, want string
	}{
		{"hysteria", v2, "hysteria2"},
		{"hysteria2", v2, "hysteria2"},
		{"hysteria2", v1, "hysteria"},
		{"hysteria", v1, "hysteria"},
		{"hysteria", noVersion, "hysteria"},
		{"hysteria2", noVersion, "hysteria2"},
	}
	for _, c := range cases {
		n, err := fetchNode(t, c.configured, c.body)
		if err != nil {
			t.Fatalf("%s: %v", c.configured, err)
		}
		if n.Type != c.want {
			t.Fatalf("configured %s, served %s: got type %s", c.configured, c.body, n.Type)
		}
		switch c.want {
		case "hysteria2":
			if n.Hysteria2 == nil || n.Hysteria != nil {
				t.Fatalf("%s: decoded as the wrong protocol", c.configured)
			}
			if c.body == v2 && (n.Hysteria2.ObfsType != "salamander" || n.Hysteria2.ObfsPassword != "p" || !n.Hysteria2.Ignore_Client_Bandwidth) {
				t.Fatalf("hysteria2 fields lost: %+v", n.Hysteria2)
			}
		case "hysteria":
			if n.Hysteria == nil || n.Hysteria2 != nil {
				t.Fatalf("%s: decoded as the wrong protocol", c.configured)
			}
		}
	}
}

// Every route action the panel offers must reach the node. Only block and
// dns did; the rest were dropped without a word.
func TestGetNodeInfo_AllRouteActions(t *testing.T) {
	body := `{"server_port":1234,"cipher":"aes-128-gcm","routes":[
	  {"id":9,"match":[],"action":"default_out","action_value":"{\"protocol\":\"blackhole\"}"},
	  {"id":1,"match":["regexp:^ads\\.","*.bad.example","domain:tracker.example","geosite:category-ads","protocol:bittorrent"],"action":"block"},
	  {"id":2,"match":["10.0.0.0/8","geoip:cn"],"action":"block_ip"},
	  {"id":3,"match":["25","6881-6889"],"action":"block_port"},
	  {"id":4,"match":["bittorrent","quic"],"action":"protocol"},
	  {"id":5,"match":["geosite:netflix"],"action":"route","action_value":"{\"protocol\":\"freedom\"}"},
	  {"id":6,"match":["1.1.1.1"],"action":"route_ip","action_value":"{\"protocol\":\"freedom\"}"},
	  {"id":7,"match":["x.example"],"action":"route","action_value":""},
	  {"id":8,"match":["x"],"action":"teleport"}
	]}`
	n, err := fetchNode(t, "shadowsocks", body)
	if err != nil {
		t.Fatal(err)
	}
	eq := func(what string, got, want []string) {
		t.Helper()
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", what, got, want)
		}
	}
	eq("regexp", n.Rules.Regexp, []string{"^ads\\.", "*.bad.example"})
	eq("domain", n.Rules.Domain, []string{"domain:tracker.example", "geosite:category-ads"})
	eq("ip", n.Rules.IP, []string{"10.0.0.0/8", "geoip:cn"})
	eq("port", n.Rules.Port, []string{"25", "6881-6889"})
	eq("protocol", n.Rules.Protocol, []string{"bittorrent", "bittorrent", "quic"})

	var got []string
	for _, r := range n.RouteRules {
		got = append(got, r.Action+":"+strings.Join(r.Match, ","))
	}
	// default_out last, whatever its place in the panel's list; the route
	// with no outbound and the unknown action are skipped.
	eq("route rules", got, []string{"route:geosite:netflix", "route_ip:1.1.1.1", "default_out:"})
	if string(n.RouteRules[2].Outbound) != `{"protocol":"blackhole"}` {
		t.Errorf("default_out outbound = %s", n.RouteRules[2].Outbound)
	}
}
