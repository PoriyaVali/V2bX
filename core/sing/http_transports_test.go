package sing

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

// socks5Connect opens a CONNECT to target, an IPv4 address and port, through
// a SOCKS5 inbound on port.
func socks5Connect(port int, target string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(ps)
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	reply := make([]byte, 10)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := io.ReadFull(c, reply[:2]); err != nil {
		c.Close()
		return nil, err
	}
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	if _, err := c.Write(binary.BigEndian.AppendUint16(req, uint16(p))); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("connect refused: %v", err)
	}
	return c, nil
}

// 🔴 Users reach VLESS, VMess and Trojan nodes over WebSocket, and VLESS and
// VMess nodes over HTTPUpgrade. They were all refused from v1.10.0 on: these
// transports hand their connections on with a fresh context, which lost the
// node generation the hook requires, and the hook closed each connection
// without a word. TCP and gRPC nodes kept working, so only these nodes went
// dark.
func TestSing_WebSocketAndHTTPUpgradeNodesAdmitUsers(t *testing.T) {
	limiter.Init()
	sc := conf.NewSingConfig()
	sc.AllowPrivateDestinations = true // the echo server is on loopback
	sc.LogConfig.Disabled = true
	c, err := New(&conf.CoreConfig{Type: "sing", SingConfig: sc})
	if err != nil {
		t.Fatal(err)
	}
	b := c.(*Sing)
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	user := panel.UserInfo{Id: 7, Uuid: "3b1f6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10"}
	for _, tc := range []struct {
		protocol, network, settings, transport string
	}{
		{"vless", "ws", `{"path":"/ws","headers":{"Host":"node.test"}}`, `{"type":"ws","path":"/ws","headers":{"Host":["node.test"]}}`},
		{"vmess", "ws", `{"path":"/ws","headers":{"Host":"node.test"}}`, `{"type":"ws","path":"/ws","headers":{"Host":["node.test"]}}`},
		{"trojan", "ws", `{"path":"/ws","headers":{"Host":"node.test"}}`, `{"type":"ws","path":"/ws","headers":{"Host":["node.test"]}}`},
		{"vless", "httpupgrade", `{"path":"/up","host":"node.test"}`, `{"type":"httpupgrade","path":"/up","host":"node.test"}`},
		{"vmess", "httpupgrade", `{"path":"/up","host":"node.test"}`, `{"type":"httpupgrade","path":"/up","host":"node.test"}`},
	} {
		t.Run(tc.protocol+"/"+tc.network, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := ln.Addr().(*net.TCPAddr).Port
			_ = ln.Close()
			tag := "http-transport-" + tc.protocol + "-" + tc.network
			info := &panel.NodeInfo{Type: tc.protocol}
			credential := `"uuid":"` + user.Uuid + `"`
			switch tc.protocol {
			case "trojan":
				tr := &panel.TrojanNode{Network: tc.network, NetworkSettings: json.RawMessage(tc.settings)}
				tr.ServerPort = port
				info.Trojan, info.Common = tr, &tr.CommonNode
				credential = `"password":"` + user.Uuid + `"`
			default:
				v := &panel.VAllssNode{Network: tc.network, NetworkSettings: json.RawMessage(tc.settings)}
				v.ServerPort = port
				info.VAllss, info.Common = v, &v.CommonNode
			}
			options := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}
			if tc.protocol == "trojan" {
				// Trojan always runs over TLS.
				cert, key := decoyTestCert(t)
				info.Security = panel.Tls
				options.CertConfig = &conf.CertConfig{CertMode: "file", CertDomain: "node.test", CertFile: cert, KeyFile: key}
			}
			limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
			t.Cleanup(func() { limiter.DeleteLimiter(tag) })
			if err := b.AddNode(tag, info, options); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.DelNode(tag) })
			if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
				t.Fatal(err)
			}

			ln, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			socks := ln.Addr().(*net.TCPAddr).Port
			_ = ln.Close()
			tls := ""
			if tc.protocol == "trojan" {
				tls = `"tls":{"enabled":true,"server_name":"node.test","insecure":true},`
			}
			config := fmt.Sprintf(`{"log":{"disabled":true},
			  "inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],
			  "outbounds":[{"type":%q,"tag":"proxy","server":"127.0.0.1","server_port":%d,%s,%s"transport":%s}],
			  "route":{"final":"proxy"}}`, socks, tc.protocol, port, credential, tls, tc.transport)
			ctx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(),
				include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
			clientOptions, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
			if err != nil {
				t.Fatal(err)
			}
			client, err := box.New(box.Options{Context: ctx, Options: clientOptions})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Start(); err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			conn, err := socks5Connect(socks, echo.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 4)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
				t.Fatalf("echo = %q, %v: the node refused its user", got, err)
			}
		})
	}
}
