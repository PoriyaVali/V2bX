package sing

import (
	"bytes"
	"crypto/tls"
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

// clientHello is the first flight a TLS client sends for serverName.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go tls.Client(c, &tls.Config{ServerName: serverName}).Handshake()
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 4096)
	n, err := s.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	s.Close()
	return b[:n]
}

// 🔴 The panel's domain and protocol rules on a sing node, for traffic whose
// domain or protocol only sniffing reveals.
//
// The node asked for sniffing through the listener's legacy inbound fields,
// which sing-box 1.13 removed: they still exist in the Go struct, so the
// build kept compiling, but nothing reads them. Sniffing was simply off. A
// client that resolves names itself and connects to the IP (any TUN-mode
// app) walked past every "block domain" rule, and "protocol: bittorrent"
// never matched anything.
func TestSing_SniffedDomainAndProtocolRulesApply(t *testing.T) {
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

	m, _ := shadowaead.New("aes-128-gcm", nil, user.Uuid)
	// reaches sends first to the echo server's IP and reports whether it came
	// back - i.e. whether the node let the connection through.
	reaches := func(first []byte) bool {
		raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Fatal(err)
		}
		conn := m.DialEarlyConn(raw, M.ParseSocksaddr(echo.Addr().String()))
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(first); err != nil {
			return false
		}
		got := make([]byte, len(first))
		_, err = io.ReadFull(conn, got)
		return err == nil && bytes.Equal(got, first)
	}

	hello := clientHello(t, "blocked.example")
	torrent := append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...)

	for name, first := range map[string][]byte{"TLS": hello, "BitTorrent": torrent} {
		if !reaches(first) {
			t.Fatalf("%s: not reachable through the node with no rules", name)
		}
	}
	for name, c := range map[string]struct {
		rules *panel.Rules
		first []byte
	}{
		"domain rule, client connects to the IP": {&panel.Rules{Domain: []string{"domain:blocked.example"}}, hello},
		"protocol rule bittorrent":               {&panel.Rules{Protocol: []string{"bittorrent"}}, torrent},
		"protocol rule tls":                      {&panel.Rules{Protocol: []string{"tls"}}, hello},
	} {
		_ = l.UpdateRule(c.rules)
		if reaches(c.first) {
			t.Errorf("%s: a connection the rule blocks went through", name)
		}
	}
	_ = l.UpdateRule(&panel.Rules{Domain: []string{"domain:other.example"}, Protocol: []string{"quic"}})
	if !reaches(hello) || !reaches(torrent) {
		t.Fatal("rules that match neither connection blocked it")
	}
}
