package mihomo

import (
	"context"
	"github.com/PoriyaVali/V2bX/api/panel"
	C "github.com/metacubex/mihomo/constant"
	S "github.com/metacubex/mihomo/transport/socks5"
	"net"
	"testing"
	"time"
)

func TestSOCKSAssociationsSharingSourceSocketKeepSeparateRelays(t *testing.T) {
	_, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	destination := udpEcho(t)
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	associate := func() (*net.TCPConn, net.Addr) {
		c, e := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: info.Common.ServerPort})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		relay, e := S.ClientHandshake(c, S.ParseAddrToSocksAddr(pc.LocalAddr()), S.CmdUDPAssociate, &S.User{Username: subscriber.Uuid, Password: subscriber.Uuid})
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Time{})
		return c, relay.UDPAddr()
	}
	first, a := associate()
	_, b := associate()
	exchange := func(relay net.Addr, value string) {
		data, e := S.EncodeUDPPacket(S.ParseAddrToSocksAddr(destination), []byte(value))
		if e != nil {
			t.Fatal(e)
		}
		_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
		if _, e = pc.WriteTo(data, relay); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 65535)
		count, from, e := pc.ReadFrom(buf)
		if e != nil {
			t.Fatal(e)
		}
		if from.String() != relay.String() {
			t.Fatalf("response crossed UDP associations: got relay %s want %s", from, relay)
		}
		_, payload, e := S.DecodeUDPPacket(buf[:count])
		if e != nil || string(payload) != value {
			t.Fatalf("payload=%q error=%v", payload, e)
		}
	}
	exchange(a, "first association")
	exchange(b, "second association")
	_ = first.Close()
	exchange(b, "other association remains live")
}

func TestMuxUDPSessionsKeepSeparateReplies(t *testing.T) {
	_, info, _ := fixture(t, "vmess", []panel.UserInfo{subscriber})
	destination := udpEcho(t)
	p := client(t, info, subscriber, map[string]any{"smux": map[string]any{"enabled": true, "protocol": "smux", "max-connections": 1}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	m := metadata(t, destination.String())
	m.NetWork = C.UDP
	a, e := p.ListenPacketContext(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := p.ListenPacketContext(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	for i, pc := range []net.PacketConn{a, b} {
		_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
		if _, e = pc.WriteTo([]byte{byte(i + 1)}, destination); e != nil {
			t.Fatal(e)
		}
	}
	for i, pc := range []net.PacketConn{a, b} {
		buffer := make([]byte, 10)
		n, _, e := pc.ReadFrom(buffer)
		if e != nil {
			t.Fatal(e)
		}
		if n != 1 || buffer[0] != byte(i+1) {
			t.Fatalf("mux UDP stream %d received %v", i, buffer[:n])
		}
	}
	_ = a.Close()
	if _, e = b.WriteTo([]byte("live"), destination); e != nil {
		t.Fatal(e)
	}
	buffer := make([]byte, 10)
	n, _, e := b.ReadFrom(buffer)
	if e != nil || string(buffer[:n]) != "live" {
		t.Fatalf("surviving mux UDP stream=%q err=%v", buffer[:n], e)
	}
}
