package sing

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
)

// relayedConn is the relay's side of a connection: its PROXY v2 header goes
// out in the same write as the client's first bytes.
type relayedConn struct {
	net.Conn
	header []byte
}

func (c *relayedConn) Write(b []byte) (int, error) {
	if c.header != nil {
		first := append(c.header, b...)
		c.header = nil
		if _, err := c.Conn.Write(first); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func proxyV2Header(client netip4) []byte {
	h := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0, 12}
	h = append(h, client.ip[:]...)
	h = append(h, 127, 0, 0, 1)
	h = binary.BigEndian.AppendUint16(h, client.port)
	return binary.BigEndian.AppendUint16(h, 443)
}

type netip4 struct {
	ip   [4]byte
	port uint16
}

// 🔴 Shadowsocks 2022 nodes take connections from loopback with the node's
// default options, PROXY protocol on: a local tunnel's, which sends no
// header, and the relay's, whose header arrives with the client's first
// bytes. Both failed with "bad header": the header reader read ahead into a
// 52-byte buffer, and Shadowsocks 2022 takes its whole request header, 59 or
// 75 bytes, from its first read.
func TestSS2022FromLoopbackWithTheDefaultProxyProtocol(t *testing.T) {
	limiter.Init()
	sc := conf.NewSingConfig()
	sc.AllowPrivateDestinations = true
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
	for cipher, keyLength := range map[string]int{"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32} {
		serverKey := base64.StdEncoding.EncodeToString([]byte("a server key of thirty-two bytes")[:keyLength])
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		ss := &panel.ShadowsocksNode{Cipher: cipher, ServerKey: serverKey}
		ss.ServerPort = port
		info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
		tag := "ss2022-loopback-" + cipher
		limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
		t.Cleanup(func() { limiter.DeleteLimiter(tag) })
		if !conf.NewSingOptions().ProxyProtocol {
			t.Fatal("this test is about the default, PROXY protocol on")
		}
		if err := b.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}); err != nil {
			t.Fatal(err)
		}
		if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
		method, err := shadowaead_2022.NewWithPassword(cipher, serverKey+":"+base64.StdEncoding.EncodeToString([]byte(user.Uuid[:keyLength])), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, relayed := range []bool{false, true} {
			name := cipher + "/local tunnel, no header"
			if relayed {
				name = cipher + "/relay, header with the first bytes"
			}
			t.Run(name, func(t *testing.T) {
				raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				var under net.Conn = raw
				if relayed {
					under = &relayedConn{Conn: raw, header: proxyV2Header(netip4{ip: [4]byte{5, 127, 1, 1}, port: 40000})}
				}
				conn, err := method.DialConn(under, M.ParseSocksaddr(echo.Addr().String()))
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 4)
				if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
					t.Fatalf("echo = %q, %v; the node refused the connection", got, err)
				}
			})
		}
	}
}
