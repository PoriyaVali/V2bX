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

// The panel's block_ip and block_port rules, enforced on a real sing node.
// The node used to drop them on the floor.
func TestSing_PanelBlockRulesRefuseConnections(t *testing.T) {
	b, info, port := ssNode(t, true)
	user := panel.UserInfo{Id: 7, Uuid: "3b1f6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10"}
	b.AddUsers(&vCore.AddUsersParams{Tag: "ss", Users: []panel.UserInfo{user}, NodeInfo: info})
	limiter.AddLimiter("ss", &conf.LimitConfig{}, []panel.UserInfo{user}, map[int]int{})
	t.Cleanup(func() { limiter.DeleteLimiter("ss") })
	l, err := limiter.GetLimiter("ss")
	if err != nil {
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
	_, echoPort, _ := net.SplitHostPort(echo.Addr().String())

	m, _ := shadowaead.New("aes-128-gcm", nil, user.Uuid)
	reaches := func() bool {
		raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Fatal(err)
		}
		conn := m.DialEarlyConn(raw, M.ParseSocksaddr(echo.Addr().String()))
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		msg := []byte("ping")
		if _, err := conn.Write(msg); err != nil {
			return false
		}
		_, err = io.ReadFull(conn, msg)
		return err == nil && string(msg) == "ping"
	}

	if !reaches() {
		t.Fatal("the echo server is not reachable through the node with no rules")
	}
	for name, rules := range map[string]*panel.Rules{
		"block_ip":                         {IP: []string{"127.0.0.0/8"}},
		"block_port":                       {Port: []string{echoPort}},
		"block domain rule on the address": {Domain: []string{"full:127.0.0.1"}},
	} {
		_ = l.UpdateRule(rules)
		if reaches() {
			t.Errorf("%s: a connection the rule blocks went through", name)
		}
	}
	_ = l.UpdateRule(&panel.Rules{})
	if !reaches() {
		t.Fatal("clearing the rules did not let connections through again")
	}
}
