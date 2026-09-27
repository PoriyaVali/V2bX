//go:build !race

// Not under the race detector: sing-shadowsocks' multi-user service rebuilds
// its user map in place while connections iterate it (AddUsers here, then a
// connection), and -race reports that library race before this test can say
// anything about its own subject. hook_notsent_test.go covers the hook under
// -race without the library.

package sing

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

// A subscriber's connection gets TCP_NOTSENT_LOWAT on its socket, set by the
// hook as the connection is routed.
func TestSing_NotSentLowatReachesTheConnection(t *testing.T) {
	const uuid = "3b1f6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10"
	limiter.Init()
	users := []panel.UserInfo{{Id: 1, Uuid: uuid}}
	limiter.AddLimiter("ss", &conf.LimitConfig{}, users, map[int]int{})
	t.Cleanup(func() { limiter.DeleteLimiter("ss") })

	sc := conf.NewSingConfig()
	sc.AllowPrivateDestinations = true // the echo server is on loopback
	c, err := New(&conf.CoreConfig{Type: "sing", SingConfig: sc})
	if err != nil {
		t.Fatal(err)
	}
	b := c.(*Sing)
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	ss := &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
	ss.ServerPort = port
	info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
	so := conf.NewSingOptions()
	// This client dials from loopback, which the PROXY-protocol reader treats
	// as the relay and wraps. Off, the connection is what a direct user gets.
	// (A relayed user's socket is the relay's loopback one; the socket facing
	// the user is on the relay, so nothing here should touch it.)
	so.ProxyProtocol = false
	if err := b.AddNode("ss", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: so}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}

	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	before := notSentLowatSet.Load()
	m, _ := shadowaead.New("aes-128-gcm", nil, uuid)
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	conn := m.DialEarlyConn(raw, M.ParseSocksaddr(echo.Addr().String()))
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("no echo through the node: %v", err)
	}
	if notSentLowatSet.Load() == before {
		t.Fatal("the connection's socket never got TCP_NOTSENT_LOWAT")
	}
}
