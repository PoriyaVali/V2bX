package xray

import (
	"context"
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
	"github.com/PoriyaVali/V2bX/internal/tcpmeter"
	"github.com/PoriyaVali/V2bX/limiter"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// vlessTestNode is this core with one VLESS node and one user, and an Xray
// client configured for it.
type vlessTestNode struct {
	x      *Xray
	tag    string
	info   *panel.NodeInfo
	users  []panel.UserInfo
	client *core.Instance
}

// vlessTransports are VLESS as Irboard's form offers it: what the node is
// given, and the client's stream settings. Only over TLS or WebSocket does
// VLESS write straight to a connection that closes.
var vlessTransports = map[string]struct {
	network, settings, flow string
	tls                     bool
	stream                  string
}{
	"tcp":         {network: "tcp", stream: `{"network":"tcp"}`},
	"httpupgrade": {network: "httpupgrade", settings: `{"path":"/up"}`, stream: `{"network":"httpupgrade","httpupgradeSettings":{"path":"/up"}}`},
	"xhttp":       {network: "xhttp", settings: `{"path":"/xh","mode":"auto"}`, stream: `{"network":"xhttp","xhttpSettings":{"path":"/xh","mode":"auto"}}`},
	"tls":         {network: "tcp", tls: true, stream: `{"network":"tcp"}`},
	"tls vision":  {network: "tcp", tls: true, flow: "xtls-rprx-vision", stream: `{"network":"tcp"}`},
}

// vlessNode runs this core with one VLESS node over the named transport and
// one user, at speedLimit Mbit/s (0 for none), and an Xray client for it.
func vlessNode(t *testing.T, transport string, speedLimit int) vlessTestNode {
	t.Helper()
	tr, ok := vlessTransports[transport]
	if !ok {
		t.Fatalf("no transport %q", transport)
	}
	limiter.Init()
	n := vlessTestNode{tag: "e2e-vless", users: []panel.UserInfo{{Id: 1, Uuid: e2eUUID, SpeedLimit: speedLimit}}}
	limiter.AddLimiter(n.tag, &conf.LimitConfig{}, n.users, map[int]int{})
	t.Cleanup(func() { limiter.DeleteLimiter(n.tag) })
	c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: conf.NewXrayConfig()})
	if err != nil {
		t.Fatal(err)
	}
	n.x = c.(*Xray)
	if err := n.x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.x.Close() })

	port := freePort(t)
	v := &panel.VAllssNode{Network: tr.network, Flow: tr.flow}
	if tr.settings != "" {
		v.NetworkSettings = json.RawMessage(tr.settings)
	}
	v.ServerPort = port
	opts := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
	opts.XrayOptions.DisableSniffing = true
	security, stream := panel.None, tr.stream
	if tr.tls {
		certFile, keyFile, sum := xhttpCertificate(t)
		security, v.Tls = panel.Tls, panel.Tls
		opts.CertConfig = &conf.CertConfig{CertMode: "file", CertDomain: xhttpTestHost, CertFile: certFile, KeyFile: keyFile}
		stream = fmt.Sprintf(`{"network":"tcp","security":"tls","tlsSettings":{"serverName":%q,"fingerprint":"chrome","pinnedPeerCertSha256":%q}}`, xhttpTestHost, sum)
	}
	n.info = &panel.NodeInfo{Type: "vless", Security: security, VAllss: v, Common: &v.CommonNode}
	if err := n.x.AddNode(n.tag, n.info, opts); err != nil {
		t.Fatalf("the node did not start: %v", err)
	}
	if _, err := n.x.AddUsers(&vCore.AddUsersParams{Tag: n.tag, Users: n.users, NodeInfo: n.info}); err != nil {
		t.Fatal(err)
	}
	// The targets are on loopback, which the node's own outbound refuses.
	if err := n.x.removeOutbound(n.tag); err != nil {
		t.Fatal(err)
	}
	allow := json.RawMessage(`{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`)
	ob, err := (&coreConf.OutboundDetourConfig{Protocol: "freedom", Tag: n.tag, Settings: &allow}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.x.addOutbound(ob); err != nil {
		t.Fatal(err)
	}

	raw := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"encryption":"none","flow":%q}]}]},"streamSettings":%s}]}`,
		port, e2eUUID, tr.flow, stream)
	var cfg coreConf.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	pb, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	if n.client, err = core.New(pb); err != nil {
		t.Fatal(err)
	}
	if err := n.client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.client.Close() })
	return n
}

// dial connects through the node to target. The connection lasts as long as
// the test: an Xray client's connection ends with the context it was dialled
// with.
func (n vlessTestNode) dial(t *testing.T, target string) net.Conn {
	t.Helper()
	host, p, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(p)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn, err := core.Dial(ctx, n.client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// remove takes the user off the node, as the controller does when the panel
// stops listing them.
func (n vlessTestNode) remove(t *testing.T) {
	t.Helper()
	if err := n.x.DelUsers(n.users, n.tag, n.info); err != nil {
		t.Fatal(err)
	}
	l, err := limiter.GetLimiter(n.tag)
	if err != nil {
		t.Fatal(err)
	}
	l.UpdateUser(n.tag, nil, n.users)
}

// A user the panel removes loses the connections they have open. The
// dispatcher closed a VLESS link's writer, which closes the connection only
// where VLESS writes straight to one that closes: over TLS or WebSocket.
// Over plain TCP, HTTPUpgrade and XHTTP, and under Vision, the writer is a
// wrapper with no Close: the removed user kept every open connection for as
// long as they went on using it.
func TestRemovedUsersVLESSConnectionsEnd(t *testing.T) {
	for _, transport := range []string{"tcp", "httpupgrade", "xhttp", "tls", "tls vision"} {
		t.Run(transport, func(t *testing.T) {
			n := vlessNode(t, transport, 0)
			conn := n.dial(t, echoServer(t))
			if err := echoThrough(conn); err != nil {
				t.Fatalf("before the removal: %v", err)
			}
			n.remove(t)
			// An Xray client's connection has no deadlines of its own.
			echoed := make(chan error, 1)
			go func() {
				if _, err := conn.Write([]byte("ping")); err != nil {
					echoed <- err
					return
				}
				_, err := io.ReadFull(conn, make([]byte, 4))
				echoed <- err
			}()
			select {
			case err := <-echoed:
				if err == nil {
					t.Fatal("the removed user's connection still carries traffic")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the removed user's connection was left open")
			}
			waitLinksOf(t, n.x, n.tag, 0)
		})
	}
}

func waitLinksOf(t *testing.T, x *Xray, tag string, want int) {
	t.Helper()
	waitLinks(t, x, tag, want)
}

// A user's speed limit holds their uploads as well as their downloads. A
// VLESS link had the limit on its writer only, so an upload ran at full speed
// whatever the plan allowed. 1 Mbit/s is 125 kB/s after a 64 KiB burst: 256
// KiB take a second and a half.
func TestVLESSSpeedLimitHoldsUploadsToo(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = tcpmeter.Serve(c) }()
		}
	}()
	n := vlessNode(t, "tcp", 1)
	for direction, move := range map[string]func(net.Conn, int) (time.Duration, error){"upload": tcpmeter.Upload, "download": tcpmeter.Download} {
		conn := n.dial(t, ln.Addr().String())
		watchdog := time.AfterFunc(20*time.Second, func() { conn.Close() })
		took, err := move(conn, 256<<10)
		watchdog.Stop()
		conn.Close()
		if err != nil {
			t.Fatalf("%s: %v", direction, err)
		}
		if took < time.Second {
			t.Errorf("a 256 KiB %s took %v at 1 Mbit/s: it was not limited", direction, took.Round(time.Millisecond))
		}
	}
}

// What a user ran up since the node's last report is still reported once the
// panel removes them. Their counter was deleted with them: up to a whole
// report interval of traffic was never billed.
func TestRemovedUsersTrafficIsStillReported(t *testing.T) {
	const size = 64 << 10
	transfer := func(t *testing.T, conn net.Conn) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			_, err := io.ReadFull(conn, make([]byte, size))
			done <- err
		}()
		if _, err := conn.Write(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("nothing was echoed")
		}
	}
	check := func(t *testing.T, x *Xray, tag string) {
		t.Helper()
		traffic, err := x.GetUserTrafficSlice(tag, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(traffic) != 1 || traffic[0].UID != 1 || traffic[0].Upload < size || traffic[0].Download < size {
			t.Fatalf("reported %+v after the removal, want user 1 with at least %d bytes each way", traffic, size)
		}
		// Reported once; the connection is closed, so nothing follows.
		deadline := time.Now().Add(3 * time.Second)
		for {
			again, err := x.GetUserTrafficSlice(tag, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(again) == 0 {
				return
			}
			if again[0].Upload >= size || time.Now().After(deadline) {
				t.Fatalf("reported %+v again", again)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	t.Run("vless", func(t *testing.T) {
		n := vlessNode(t, "tcp", 0)
		transfer(t, n.dial(t, echoServer(t)))
		n.remove(t)
		check(t, n.x, n.tag)
	})
	t.Run("shadowsocks", func(t *testing.T) {
		x, tag, port := xrayNode(t, 0)
		conn, ok := dialThrough(t, port, echoServer(t))
		if !ok {
			t.Fatal("the connection failed")
		}
		defer conn.Close()
		transfer(t, conn)
		if err := x.DelUsers([]panel.UserInfo{{Id: 1, Uuid: e2eUUID}}, tag, &panel.NodeInfo{Type: "shadowsocks"}); err != nil {
			t.Fatal(err)
		}
		check(t, x, tag)
	})
}
