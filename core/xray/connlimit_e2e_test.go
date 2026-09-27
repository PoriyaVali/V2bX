package xray

import (
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/common/sockopt"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/core/xray/app/dispatcher"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/app/proxyman"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const e2eUUID = "3b1f6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10"

// echoServer answers every connection with whatever it is sent.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// xrayNode runs a real xray core with one shadowsocks node and one user.
func xrayNode(t *testing.T, connLimit int) (*Xray, string, int) {
	t.Helper()
	limiter.Init()
	const tag = "e2e-ss"
	users := []panel.UserInfo{{Id: 1, Uuid: e2eUUID}}
	limiter.AddLimiter(tag, &conf.LimitConfig{ConnLimit: connLimit}, users, map[int]int{})
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })

	c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: conf.NewXrayConfig()})
	if err != nil {
		t.Fatal(err)
	}
	x := c.(*Xray)
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })

	port := freePort(t)
	ss := &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
	ss.ServerPort = port
	info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
	xo := conf.NewXrayOptions()
	xo.DisableSniffing = true
	if err := x.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", XrayOptions: xo}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	// The node's outbound refuses private destinations, as it should in
	// production; the echo server here is on loopback, so let that through.
	if err := x.removeOutbound(tag); err != nil {
		t.Fatal(err)
	}
	settings := json.RawMessage(`{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`)
	ob, err := (&coreConf.OutboundDetourConfig{Protocol: "freedom", Tag: tag, Settings: &settings}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := x.addOutbound(ob); err != nil {
		t.Fatal(err)
	}
	return x, tag, port
}

// dialThrough opens a shadowsocks connection to target through the node and
// checks it carries data. It reports whether the node let the connection
// through.
func dialThrough(t *testing.T, port int, target string) (net.Conn, bool) {
	t.Helper()
	m, err := shadowaead.New("aes-128-gcm", nil, e2eUUID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	conn := m.DialEarlyConn(raw, M.ParseSocksaddr(target))
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		conn.Close()
		return nil, false
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		conn.Close()
		return nil, false
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, true
}

func openLinks(x *Xray, tag string) int {
	v, ok := x.dispatcher.LinkManagers.Load(format.UserTag(tag, e2eUUID))
	if !ok {
		return 0
	}
	return v.(*dispatcher.LinkManager).Len()
}

func waitLinks(t *testing.T, x *Xray, tag string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for openLinks(x, tag) != want {
		if time.Now().After(deadline) {
			t.Fatalf("user holds %d open connection(s) on the node, want %d", openLinks(x, tag), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ConnLimit caps one user's simultaneous connections on an xray node. It was
// only ever enforced by the sing core; here it did nothing.
func TestXray_ConnLimitCapsOpenConnections(t *testing.T) {
	x, tag, port := xrayNode(t, 3)
	target := echoServer(t)

	var held []net.Conn
	for i := 0; i < 3; i++ {
		c, ok := dialThrough(t, port, target)
		if !ok {
			t.Fatalf("connection %d refused below the limit", i+1)
		}
		held = append(held, c)
	}
	waitLinks(t, x, tag, 3)
	if c, ok := dialThrough(t, port, target); ok {
		c.Close()
		t.Fatal("a 4th connection got through a ConnLimit of 3")
	}
	// Closed connections free their slot.
	held[0].Close()
	waitLinks(t, x, tag, 2)
	c, ok := dialThrough(t, port, target)
	if !ok {
		t.Fatal("a slot freed by a closed connection was not given back")
	}
	c.Close()
	for _, h := range held[1:] {
		h.Close()
	}
}

// Every connection leaves the user's set when it ends, however many come and
// go - otherwise the set grows for the life of the process and ConnLimit would
// eventually refuse a user who holds nothing open.
func TestXray_ClosedConnectionsAreForgotten(t *testing.T) {
	x, tag, port := xrayNode(t, 0)
	target := echoServer(t)
	for i := 0; i < 50; i++ {
		c, ok := dialThrough(t, port, target)
		if !ok {
			t.Fatalf("connection %d refused", i+1)
		}
		c.Close()
	}
	waitLinks(t, x, tag, 0)
}

// Removing the user closes what they have open, and nothing more gets in on
// the old set.
func TestXray_DelUsersClosesOpenConnections(t *testing.T) {
	x, tag, port := xrayNode(t, 0)
	target := echoServer(t)
	c, ok := dialThrough(t, port, target)
	if !ok {
		t.Fatal("setup: connection refused")
	}
	defer c.Close()
	waitLinks(t, x, tag, 1)
	if err := x.DelUsers([]panel.UserInfo{{Id: 1, Uuid: e2eUUID}}, tag, nil); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the removed user's connection is still open")
	}
}

// An unset AccessPath means no access log. xray reads "" as "log every
// connection to the console", which is what a node got whatever its level.
func TestAccessLogPath(t *testing.T) {
	cases := map[string]string{
		"":                      "none",
		"  ":                    "none",
		"console":               "",
		"STDOUT":                "",
		"/var/log/v2bx/acc.log": "/var/log/v2bx/acc.log",
		"none":                  "none",
	}
	for in, want := range cases {
		if got := accessLogPath(in); got != want {
			t.Errorf("accessLogPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Idle keep-alive connections are kept as long as xray itself would keep them.
func TestDefaultConnIdle(t *testing.T) {
	if got := conf.NewXrayConfig().ConnectionConfig.ConnIdle; got != 300 {
		t.Fatalf("default connIdle = %d s, want 300", got)
	}
}

// A subscriber's connection gets TCP_NOTSENT_LOWAT on its own socket, and the
// node's listener gets the congestion control its connections inherit.
func TestXray_SocketTuningReachesConnections(t *testing.T) {
	x, tag, port := xrayNode(t, 0)
	if _, ok := x.dispatcher.NotSentLowat.Load(tag); !ok {
		t.Skip("TCP_NOTSENT_LOWAT not available on this kernel")
	}
	target := echoServer(t)
	before := x.dispatcher.NotSentLowatSet()
	c, ok := dialThrough(t, port, target)
	if !ok {
		t.Fatal("connection refused")
	}
	c.Close()
	if x.dispatcher.NotSentLowatSet() == before {
		t.Fatal("the connection's socket never got TCP_NOTSENT_LOWAT")
	}
}

func TestBuildInbound_CongestionControl(t *testing.T) {
	ss := &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
	ss.ServerPort = 1234
	info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
	cc := func(setting string) string {
		xo := conf.NewXrayOptions()
		xo.TCPCongestion = setting
		in, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", XrayOptions: xo}, info, "t")
		if err != nil {
			t.Fatalf("TCPCongestion %q: %v", setting, err)
		}
		rs, err := in.ReceiverSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		return rs.(*proxyman.ReceiverConfig).GetStreamSettings().GetSocketSettings().GetTcpCongestion()
	}
	want := ""
	if sockopt.Congestion("bbr") {
		want = "bbr"
	}
	if got := cc(""); got != want {
		t.Errorf("default congestion = %q, want %q", got, want)
	}
	if got := cc("none"); got != "" {
		t.Errorf(`"none" set %q, want the system default`, got)
	}
	// An algorithm the kernel lacks must not reach xray, which would fail
	// the listen and take the node down.
	if got := cc("no-such-algorithm"); got != "" {
		t.Errorf("an unavailable algorithm was passed to xray: %q", got)
	}
}
