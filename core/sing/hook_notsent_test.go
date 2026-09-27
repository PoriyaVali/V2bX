package sing

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

// The hook sets TCP_NOTSENT_LOWAT on the socket under a routed connection,
// through the wrappers sing puts around it, for inbounds that asked for it.
func TestHook_SetsNotSentLowatOnTheSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, _ := net.Dial("tcp", ln.Addr().String())
	defer client.Close()
	server, _ := ln.Accept()
	defer server.Close()

	h := &HookServer{}
	h.notSentLowat.Store("in", 16384)
	m := adapter.InboundContext{Inbound: "in", User: "u", Source: M.ParseSocksaddr("1.2.3.4:5")}
	before := notSentLowatSet.Load()
	h.RoutedConnection(context.Background(), bufio.NewExtendedConn(server), m, nil, nil)

	rc, _ := server.(*net.TCPConn).SyscallConn()
	var v int
	rc.Control(func(fd uintptr) { v, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT) })
	if v != 16384 {
		t.Fatalf("socket has TCP_NOTSENT_LOWAT %d, want 16384", v)
	}
	if notSentLowatSet.Load() != before+1 {
		t.Fatal("not counted")
	}

	// An inbound with the option off leaves the socket alone.
	h.notSentLowat.Delete("in")
	server2c, _ := net.Dial("tcp", ln.Addr().String())
	defer server2c.Close()
	server2, _ := ln.Accept()
	defer server2.Close()
	h.RoutedConnection(context.Background(), server2, m, nil, nil)
	rc2, _ := server2.(*net.TCPConn).SyscallConn()
	rc2.Control(func(fd uintptr) { v, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT) })
	if v == 16384 {
		t.Fatal("set on an inbound that did not ask for it")
	}
}
