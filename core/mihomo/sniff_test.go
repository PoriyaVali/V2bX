package mihomo

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	C "github.com/metacubex/mihomo/constant"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
)

// tlsClientHello is the first flight a TLS client sends for serverName.
func tlsClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() { _ = tls.Client(c, &tls.Config{ServerName: serverName}).Handshake(); _ = c.Close() }()
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 8192)
	count, e := s.Read(b)
	if e != nil {
		t.Fatal(e)
	}
	return b[:count]
}

// quicInitials returns the datagrams a QUIC client sends first to reach
// serverName: one, or more when its ClientHello does not fit in one.
func quicInitials(t *testing.T, serverName string, curves ...tls.CurveID) [][]byte {
	t.Helper()
	capture, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer capture.Close()
	local, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer local.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = quic.Dial(ctx, local, capture.LocalAddr(), &tls.Config{ServerName: serverName, NextProtos: []string{"h3"}, CurvePreferences: curves}, nil)
	}()
	var packets [][]byte
	b := make([]byte, 4096)
	_ = capture.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		count, _, e := capture.ReadFrom(b)
		if e != nil {
			break
		}
		packets = append(packets, append([]byte(nil), b[:count]...))
		// The rest of the first flight follows at once; a retransmission
		// comes a probe timeout later.
		_ = capture.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	}
	if len(packets) == 0 {
		t.Fatal("the QUIC client sent nothing")
	}
	return packets
}

// sniffedDomain is the server name sniffing finds in packets.
func sniffedDomain(packets [][]byte) string {
	var s adapter.InboundContext
	for _, packet := range packets {
		if e := sniff.PeekPacket(context.Background(), &s, packet, sniff.QUICClientHello); e == nil {
			return s.Domain
		}
	}
	return ""
}

// The panel's protocol rules, and its domain rules for a connection made to an
// address, apply to what sniffing finds, as they do on the sing core: a client
// that resolves names itself and connects to the IP, or that runs BitTorrent,
// is refused as there. Every protocol's stream is sniffed, so each must accept
// the read deadline sniffing sets.
func TestSniffedDomainAndProtocolRulesApplyToTCP(t *testing.T) {
	hello := tlsClientHello(t, "blocked.example")
	torrent := append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...)
	for _, protocol := range (&Core{}).Protocols() {
		t.Run(protocol, func(t *testing.T) {
			c, info, _ := fixture(t, protocol, []panel.UserInfo{subscriber})
			n, _ := c.get(t.Name())
			p := client(t, info, subscriber)
			target := tcpEcho(t)
			reaches := func(first []byte) bool {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, e := p.DialContext(ctx, metadata(t, target))
				if e != nil {
					return false
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				return roundtrip(conn, first) == nil
			}
			for name, first := range map[string][]byte{"TLS": hello, "BitTorrent": torrent} {
				if !reaches(first) {
					t.Fatalf("%s: unreachable through the node with no rules", name)
				}
			}
			for name, rule := range map[string]struct {
				rules *panel.Rules
				first []byte
			}{
				"domain rule, client connects to the IP": {&panel.Rules{Domain: []string{"domain:blocked.example"}}, hello},
				"regexp domain rule":                     {&panel.Rules{Regexp: []string{`blocked\.example$`}}, hello},
				"protocol rule bittorrent":               {&panel.Rules{Protocol: []string{"bittorrent"}}, torrent},
				"protocol rule tls":                      {&panel.Rules{Protocol: []string{"tls"}}, hello},
			} {
				if e := n.limiter.UpdateRule(rule.rules); e != nil {
					t.Fatal(e)
				}
				if reaches(rule.first) {
					t.Errorf("%s: a connection the rule refuses went through", name)
				}
			}
			if e := n.limiter.UpdateRule(&panel.Rules{Domain: []string{"domain:other.example"}, Protocol: []string{"quic", "tcp"}}); e != nil {
				t.Fatal(e)
			}
			if !reaches(hello) || !reaches(torrent) {
				t.Fatal("rules that match neither connection refused it")
			}
		})
	}
}

func TestSniffedDomainAndProtocolRulesApplyToUDP(t *testing.T) {
	single := quicInitials(t, "blocked.example", tls.X25519)
	split := quicInitials(t, "blocked.example")
	if len(single) != 1 || sniffedDomain(single) != "blocked.example" {
		t.Fatalf("a small ClientHello took %d packets, naming %q", len(single), sniffedDomain(single))
	}
	if len(split) < 2 || sniffedDomain(split) != "blocked.example" {
		t.Fatalf("a large ClientHello took %d packets, naming %q", len(split), sniffedDomain(split))
	}
	// A uTP SYN: type 4, version 1, no extension, then a connection ID, a
	// timestamp, the window size and the sequence number.
	utp := make([]byte, 20)
	utp[0] = 0x41
	binary.BigEndian.PutUint16(utp[2:], 0x1234)
	binary.BigEndian.PutUint32(utp[4:], 0x5d1c0a3b)
	binary.BigEndian.PutUint32(utp[12:], 0x00100000)
	binary.BigEndian.PutUint16(utp[16:], 1)
	plain := [][]byte{[]byte("plain datagram")}
	for _, protocol := range []string{"socks5", "mieru", "shadowquic"} {
		t.Run(protocol, func(t *testing.T) {
			c, info, _ := fixture(t, protocol, []panel.UserInfo{subscriber})
			n, _ := c.get(t.Name())
			// QUIC datagrams cannot carry a QUIC client's padded Initial packets.
			p := client(t, info, subscriber, map[string]any{"udp-over-stream": true})
			echo := udpEcho(t)
			// reaches sends packets over a new association and reports whether
			// every one came back.
			reaches := func(packets [][]byte) bool {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				m := metadata(t, echo.String())
				m.NetWork = C.UDP
				pc, e := p.ListenPacketContext(ctx, m)
				if e != nil {
					t.Fatal(e)
				}
				defer pc.Close()
				b := make([]byte, 4096)
				for _, packet := range packets {
					if _, e := pc.WriteTo(packet, echo); e != nil {
						return false
					}
					_ = pc.SetReadDeadline(time.Now().Add(time.Second))
					count, _, e := pc.ReadFrom(b)
					if e != nil || !bytes.Equal(b[:count], packet) {
						return false
					}
				}
				return true
			}
			for name, packets := range map[string][][]byte{"QUIC": single, "split QUIC": split, "uTP": {utp}, "plain": plain} {
				if !reaches(packets) {
					t.Fatalf("%s: unreachable through the node with no rules", name)
				}
			}
			for name, rule := range map[string]struct {
				rules   *panel.Rules
				packets [][]byte
			}{
				"protocol rule quic":                       {&panel.Rules{Protocol: []string{"quic"}}, single},
				"protocol rule quic, split ClientHello":    {&panel.Rules{Protocol: []string{"quic"}}, split},
				"domain rule, QUIC to the IP":              {&panel.Rules{Domain: []string{"domain:blocked.example"}}, single},
				"domain rule, split ClientHello to the IP": {&panel.Rules{Domain: []string{"domain:blocked.example"}}, split},
				"protocol rule bittorrent":                 {&panel.Rules{Protocol: []string{"bittorrent"}}, [][]byte{utp}},
				"protocol rule udp refuses every UDP flow": {&panel.Rules{Protocol: []string{"udp"}}, plain},
			} {
				if e := n.limiter.UpdateRule(rule.rules); e != nil {
					t.Fatal(e)
				}
				if reaches(rule.packets) {
					t.Errorf("%s: a flow the rule refuses went through", name)
				}
			}
			if e := n.limiter.UpdateRule(&panel.Rules{Domain: []string{"domain:other.example"}, Protocol: []string{"tls", "tcp"}}); e != nil {
				t.Fatal(e)
			}
			for name, packets := range map[string][][]byte{"QUIC": single, "split QUIC": split, "uTP": {utp}, "plain": plain} {
				if !reaches(packets) {
					t.Errorf("%s: rules that match nothing in it refused the flow", name)
				}
			}
		})
	}
}

// Sniffing must not cost a node without rules that need it anything: the
// client's first bytes are not waited for.
func TestNodesWithoutSniffedRulesDoNotWaitForTheClient(t *testing.T) {
	c, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	n, _ := c.get(t.Name())
	// A server that speaks first: the client sends nothing until it has read.
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		for {
			conn, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte("220 ready\r\n"))
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	greeting := func() time.Duration {
		conn := dial(t, client(t, info, subscriber), l.Addr().String())
		start := time.Now()
		b := make([]byte, 11)
		if _, e := io.ReadFull(conn, b); e != nil {
			t.Fatal(e)
		}
		return time.Since(start)
	}
	if e := n.limiter.UpdateRule(&panel.Rules{Port: []string{"1"}, IP: []string{"192.0.2.1"}}); e != nil {
		t.Fatal(e)
	}
	if waited := greeting(); waited > 150*time.Millisecond {
		t.Fatalf("a node whose rules need no sniffing waited %s for the client", waited)
	}
	// With a protocol rule a server-first exchange waits out the sniff timeout
	// once, as on the sing core, and is then forwarded.
	if e := n.limiter.UpdateRule(&panel.Rules{Protocol: []string{"bittorrent"}}); e != nil {
		t.Fatal(e)
	}
	if waited := greeting(); waited > 2*time.Second {
		t.Fatalf("a server-first connection waited %s", waited)
	}
}
