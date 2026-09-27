package sing

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

// ssNode runs a real sing-box core with one multi-user shadowsocks node.
func ssNode(t *testing.T, allowPrivate bool) (*Sing, *panel.NodeInfo, int) {
	t.Helper()
	limiter.Init()
	sc := conf.NewSingConfig()
	sc.AllowPrivateDestinations = allowPrivate
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
	so.ProxyProtocol = false // the test clients dial from loopback
	if err := b.AddNode("ss", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: so}); err != nil {
		t.Fatal(err)
	}
	return b, info, port
}

func fillers(from, n int) []panel.UserInfo {
	us := make([]panel.UserInfo, n)
	for i := range us {
		us[i] = panel.UserInfo{Id: 100000 + from + i, Uuid: fmt.Sprintf("%08d-0000-4c55-9b0e-6f2d7e8a9c10", from+i)}
	}
	return us
}

// 🔴 Adding and removing users while connections arrive. The multi-user
// shadowsocks service refilled its user map in place as connections
// iterated it: "fatal error: concurrent map iteration and map write" on the
// first change under load, ending the process and every node it served.
func TestSing_ShadowsocksSurvivesUserChangesUnderLoad(t *testing.T) {
	b, info, port := ssNode(t, false)
	b.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: fillers(0, 200), NodeInfo: info})
	var stop atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			junk := make([]byte, 64) // a header the node tries against every user
			for !stop.Load() {
				if conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
					conn.Write(junk)
					conn.Close()
				}
			}
		}()
	}
	deadline := time.Now().Add(3 * time.Second)
	for n := 0; time.Now().Before(deadline); n++ {
		b.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: fillers(1000+n, 1), NodeInfo: info})
		b.DelUsers(fillers(n, 1), "ss", info)
	}
	stop.Store(true)
	wg.Wait()
}

// 🔴 Traffic stays with the user who made it while other users are removed.
// Inbounds identified users by their position in a list, and a removal moved
// everyone after it: a connection authenticated just before was billed to a
// neighbour - or indexed past the end of the shorter list and panicked.
func TestSing_UserChangesDoNotMisattributeTraffic(t *testing.T) {
	b, info, port := ssNode(t, true)
	target := panel.UserInfo{Id: 7, Uuid: "3b1f6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10"}
	b.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: fillers(0, 100), NodeInfo: info})
	b.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: []panel.UserInfo{target}, NodeInfo: info})
	limiter.AddLimiter("ss", &conf.LimitConfig{}, []panel.UserInfo{target}, map[int]int{})

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

	var stop atomic.Bool
	var churn sync.WaitGroup
	churn.Add(1)
	go func() { // remove the user at the front, add one at the back, again and again
		defer churn.Done()
		for n := 0; !stop.Load(); n++ {
			b.DelUsers(fillers(n, 1), "ss", info)
			b.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: fillers(100+n, 1), NodeInfo: info})
		}
	}()
	m, _ := shadowaead.New("aes-128-gcm", nil, target.Uuid)
	var sent int64
	for i := 0; i < 60; i++ {
		raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Fatal(err)
		}
		conn := m.DialEarlyConn(raw, M.ParseSocksaddr(echo.Addr().String()))
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		msg := make([]byte, 1000)
		if _, err := conn.Write(msg); err == nil {
			if _, err := io.ReadFull(conn, msg); err == nil {
				sent += int64(len(msg))
			}
		}
		conn.Close()
	}
	stop.Store(true)
	churn.Wait()
	time.Sleep(200 * time.Millisecond) // let the last connections finish counting

	traffic, _ := b.GetUserTrafficSlice("ss", true)
	var targetBytes int64
	for _, u := range traffic {
		if u.UID != target.Id {
			t.Errorf("traffic billed to UID %d, who never connected: %+v", u.UID, u)
			continue
		}
		targetBytes += u.Upload + u.Download
	}
	if sent == 0 || targetBytes == 0 {
		t.Fatalf("no traffic for the connecting user (sent %d, counted %d)", sent, targetBytes)
	}
}

// The listener sets TCP_NOTSENT_LOWAT on every connection it accepts, so it
// covers every protocol - anytls and mux included, whose streams share one
// connection.
func TestGetInboundOptions_NotSentLowat(t *testing.T) {
	ss := &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
	info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
	lowat := func(n int) int {
		so := conf.NewSingOptions()
		so.TCPNotSentLowat = n
		in, err := getInboundOptions("t", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: so})
		if err != nil {
			t.Fatal(err)
		}
		return in.Options.(*option.ShadowsocksInboundOptions).ListenOptions.TCPNotSentLowat
	}
	if got := lowat(0); got != conf.DefaultTCPNotSentLowat {
		t.Errorf("default = %d, want %d", got, conf.DefaultTCPNotSentLowat)
	}
	if got := lowat(-1); got != 0 {
		t.Errorf("negative must leave the system default, got %d", got)
	}
	if got := lowat(65536); got != 65536 {
		t.Errorf("explicit value = %d, want 65536", got)
	}
}
