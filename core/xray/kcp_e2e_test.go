package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// freeUDPPort is a UDP port nothing listens on, for mKCP.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// A VMess node over KCP, with the settings Irboard's VMess form puts in for
// KCP as the node is served them: {"header":{"type":"none"},"seed":""}, the
// empty seed posted as null. With no KCP case in the transport switch, the
// node failed with "the network type is not vail" and never came up.
func TestVMessOverKCPWithTheFormsSettings(t *testing.T) {
	for _, settings := range []string{`{"header":{"type":"none"},"seed":null}`, `null`, `{"mtu":1350,"tti":20}`} {
		t.Run(settings, func(t *testing.T) {
			limiter.Init()
			tag := "e2e-kcp"
			users := []panel.UserInfo{{Id: 1, Uuid: e2eUUID}}
			limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
			t.Cleanup(func() { limiter.DeleteLimiter(tag) })
			c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: conf.NewXrayConfig()})
			if err != nil {
				t.Fatal(err)
			}
			x := c.(*Xray)
			if err := x.Start(); err != nil {
				t.Fatal(err)
			}
			// Closed with a session still being read, which raced in xray-core
			// until patches/xray-tls-lifecycle.patch put the receive buffer
			// under its lock.
			t.Cleanup(func() { _ = x.Close() })

			port, echo := freeUDPPort(t), echoServer(t)
			v := &panel.VAllssNode{Network: "kcp", NetworkSettings: json.RawMessage(settings)}
			v.ServerPort = port
			info := &panel.NodeInfo{Type: "vmess", Security: panel.None, VAllss: v, Common: &v.CommonNode}
			opts := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
			opts.XrayOptions.DisableSniffing = true
			if err := x.AddNode(tag, info, opts); err != nil {
				t.Fatalf("the node did not start: %v", err)
			}
			if _, err := x.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
				t.Fatal(err)
			}
			if err := x.removeOutbound(tag); err != nil {
				t.Fatal(err)
			}
			allow := json.RawMessage(`{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`)
			ob, err := (&coreConf.OutboundDetourConfig{Protocol: "freedom", Tag: tag, Settings: &allow}).Build()
			if err != nil {
				t.Fatal(err)
			}
			if err := x.addOutbound(ob); err != nil {
				t.Fatal(err)
			}

			// A VMess client over mKCP, as a share link configures it.
			raw := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"security":"auto"}]}]},"streamSettings":{"network":"kcp","kcpSettings":{}}}]}`, port, e2eUUID)
			var cfg coreConf.Config
			if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
				t.Fatal(err)
			}
			pb, err := cfg.Build()
			if err != nil {
				t.Fatal(err)
			}
			client, err := core.New(pb)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Start(); err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			host, p, _ := net.SplitHostPort(echo)
			pn, _ := strconv.Atoi(p)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(pn)))
			if err != nil {
				t.Fatal(err)
			}
			err = echoThrough(conn)
			conn.Close()
			if err != nil {
				t.Fatalf("VMess over mKCP: %v", err)
			}
		})
	}
}
