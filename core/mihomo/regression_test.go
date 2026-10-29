package mihomo

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	C "github.com/metacubex/mihomo/constant"
	S "github.com/metacubex/mihomo/transport/socks5"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Starts the node with no users so a test can replace its resolver before any
// listener goroutine exists, then admits the subscriber.
func lookupFixture(t *testing.T, protocol string, lookup func(context.Context, string, string) ([]netip.Addr, error)) (*Core, *panel.NodeInfo) {
	t.Helper()
	c, info, _ := fixture(t, protocol, nil)
	n, _ := c.get(t.Name())
	n.lookup = lookup
	if _, e := c.AddUsers(&vCore.AddUsersParams{Tag: t.Name(), Users: []panel.UserInfo{subscriber}, NodeInfo: info}); e != nil {
		t.Fatal(e)
	}
	n.limiter.UpdateUser(t.Name(), []panel.UserInfo{subscriber}, nil)
	return c, info
}

func socksAssociation(t *testing.T, info *panel.NodeInfo, source net.PacketConn) net.Addr {
	t.Helper()
	c, e := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: info.Common.ServerPort})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	relay, e := S.ClientHandshake(c, S.ParseAddrToSocksAddr(source.LocalAddr()), S.CmdUDPAssociate, &S.User{Username: subscriber.Uuid, Password: subscriber.Uuid})
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Time{})
	return relay.UDPAddr()
}

func socksDatagram(t *testing.T, source net.PacketConn, relay net.Addr, destination, payload string) {
	t.Helper()
	data, e := S.EncodeUDPPacket(S.ParseAddr(destination), []byte(payload))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = source.WriteTo(data, relay); e != nil {
		t.Fatal(e)
	}
}

// Older sing-based clients, like clients behind NAT, name an address other than
// the one their datagrams come from in UDP ASSOCIATE. The relay must still
// accept them; it pins the first datagram's port instead.
func TestSOCKSAssociationNamingAnotherAddress(t *testing.T) {
	_, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	echo, e := net.ListenPacket("udp", "127.0.0.2:0")
	if e != nil {
		t.Skip("no 127.0.0.2 loopback address:", e)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		b := make([]byte, 1500)
		for {
			count, from, e := echo.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = echo.WriteTo(b[:count], from)
		}
	}()
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	c, e := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: info.Common.ServerPort})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	bound, e := S.ClientHandshake(c, S.ParseAddrToSocksAddr(echo.LocalAddr()), S.CmdUDPAssociate, &S.User{Username: subscriber.Uuid, Password: subscriber.Uuid})
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Time{})
	socksDatagram(t, pc, bound.UDPAddr(), echo.LocalAddr().String(), "named destination")
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 128)
	count, _, e := pc.ReadFrom(b)
	if e != nil {
		t.Fatalf("datagram from the client's real port was dropped: %v", e)
	}
	if _, payload, e := S.DecodeUDPPacket(b[:count]); e != nil || string(payload) != "named destination" {
		t.Fatalf("payload=%q err=%v", payload, e)
	}
}

// Current sing-based clients send a zero port; their associations must keep working.
func TestSOCKSAssociationFromSingClient(t *testing.T) {
	_, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	destination := udpEcho(t)
	sc := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(info.Common.ServerPort)), socks.Version5, subscriber.Uuid, subscriber.Uuid)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pc, e := sc.ListenPacket(ctx, M.SocksaddrFromNet(destination))
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = pc.WriteTo([]byte("sing association"), destination); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 64)
	count, _, e := pc.ReadFrom(b)
	if e != nil || string(b[:count]) != "sing association" {
		t.Fatalf("payload=%q err=%v", b[:count], e)
	}
}

// A datagram to a name whose lookup hangs must not hold up other flows on the
// node: they share one packet queue.
func TestSlowUDPResolutionDoesNotStallOtherFlows(t *testing.T) {
	_, info := lookupFixture(t, "socks5", func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if host == "slow.test" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return net.DefaultResolver.LookupNetIP(ctx, network, host)
	})
	destination := udpEcho(t)
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	relay := socksAssociation(t, info, pc)
	socksDatagram(t, pc, relay, "slow.test:53", "stalled lookup")
	time.Sleep(100 * time.Millisecond)
	socksDatagram(t, pc, relay, destination.String(), "prompt")
	// The fixture's dial timeout is three seconds.
	_ = pc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	b := make([]byte, 128)
	count, _, e := pc.ReadFrom(b)
	if e != nil {
		t.Fatalf("flow waited behind another flow's DNS lookup: %v", e)
	}
	if _, payload, e := S.DecodeUDPPacket(b[:count]); e != nil || string(payload) != "prompt" {
		t.Fatalf("payload=%q err=%v", payload, e)
	}
}

func TestTCPFallsBackToTheNextCheckedAddress(t *testing.T) {
	_, info := lookupFixture(t, "socks5", func(context.Context, string, string) ([]netip.Addr, error) {
		// Nothing listens on 127.0.0.2: the echo server binds 127.0.0.1 only.
		return []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}, nil
	})
	_, port, _ := net.SplitHostPort(tcpEcho(t))
	conn := dial(t, client(t, info, subscriber), net.JoinHostPort("dual.test", port))
	if e := roundtrip(conn, []byte("second address")); e != nil {
		t.Fatalf("an unreachable first address failed the connection: %v", e)
	}
}

type flakyListener struct {
	net.Listener
	mu       sync.Mutex
	failures int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.failures > 0 {
		l.failures--
		l.mu.Unlock()
		return nil, errors.New("accept: too many open files")
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

func TestSOCKSListenerSurvivesTransientAcceptErrors(t *testing.T) {
	inner, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	accepted := make(chan net.Conn, 1)
	stopped := make(chan struct{})
	go func() {
		acceptLoop(&flakyListener{Listener: inner, failures: 3}, func(c net.Conn) { accepted <- c })
		close(stopped)
	}()
	c, e := net.Dial("tcp", inner.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	select {
	case s := <-accepted:
		_ = s.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("listener stopped accepting after a transient error")
	}
	_ = inner.Close()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("accept loop outlived its listener")
	}
}

// A subscriber that stops reading must not hold up a membership change: its
// pending UDP reply blocks on the stream until the node closes its sockets.
func TestMembershipChangeDoesNotWaitForAStalledClient(t *testing.T) {
	other := panel.UserInfo{Id: 18, Uuid: "5b0c5bb7-3c2f-4d0e-8a44-5f7b9a5f2e11"}
	c, info, _ := fixture(t, "vmess", []panel.UserInfo{subscriber, other})
	tag := t.Name()
	n, _ := c.get(tag)
	n.limiter.UpdateUser(tag, []panel.UserInfo{subscriber, other}, nil)
	flood, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer flood.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		b := make([]byte, 64)
		_, peer, e := flood.ReadFrom(b)
		if e != nil {
			return
		}
		datagram := make([]byte, 1200)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, e := flood.WriteTo(datagram, peer); e != nil {
				return
			}
		}
	}()
	p := client(t, info, subscriber)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	m := metadata(t, flood.LocalAddr().String())
	m.NetWork = C.UDP
	pc, e := p.ListenPacketContext(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	// Never read: the stream's buffers fill and the node's reply write blocks.
	if _, e = pc.WriteTo([]byte("start"), flood.LocalAddr()); e != nil {
		t.Fatal(e)
	}
	downloaded := func() int64 {
		v, _ := c.GetUserTrafficSlice(tag, false)
		if len(v) == 0 {
			return 0
		}
		return v[0].Download
	}
	deadline := time.Now().Add(10 * time.Second)
	for last := int64(-1); ; {
		if time.Now().After(deadline) {
			t.Fatal("reply stream never filled")
		}
		time.Sleep(300 * time.Millisecond)
		if now := downloaded(); now > 0 && now == last {
			break
		} else {
			last = now
		}
	}
	done := make(chan error, 1)
	go func() { done <- c.DelUsers([]panel.UserInfo{other}, tag, info) }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("membership change waited for a client that stopped reading")
	}
}

func TestManagedCredentialsMustCarryTheUserSecret(t *testing.T) {
	c0, e := New(&conf.CoreConfig{MihomoConfig: conf.NewMihomoConfig()})
	if e != nil {
		t.Fatal(e)
	}
	c := c0.(*Core)
	tag := t.Name()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, nil, map[int]int{})
	t.Cleanup(func() { _ = c.Close(); limiter.DeleteLimiter(tag) })
	common := panel.CommonNode{ServerPort: freePort(t)}
	options := &conf.Options{ListenIP: "127.0.0.1"}
	for _, guessable := range []panel.MihomoNode{
		{CommonNode: common, Username: "{{user_id}}", Password: "{{user_id}}"},
		{CommonNode: common, Username: "fixed-{{user_id}}", Password: "{{user_id}}-x"},
	} {
		info := &panel.NodeInfo{Type: "socks5", Common: &common, Mihomo: &guessable}
		if e := c.AddNode(tag, info, options); e == nil {
			_ = c.DelNode(tag)
			t.Fatalf("credentials without {{uuid}} accepted: %+v", guessable)
		}
	}
	readable := &panel.NodeInfo{Type: "socks5", Common: &common, Mihomo: &panel.MihomoNode{CommonNode: common, Username: "user{{user_id}}"}}
	if e := c.AddNode(tag, readable, options); e != nil {
		t.Fatalf("a public username with the default UUID password was rejected: %v", e)
	}
}

func TestRemovingAnAbsentUserKeepsSessions(t *testing.T) {
	c, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	conn := dial(t, client(t, info, subscriber), tcpEcho(t))
	if e := roundtrip(conn, []byte("before")); e != nil {
		t.Fatal(e)
	}
	if e := c.DelUsers([]panel.UserInfo{{Id: 99, Uuid: "a9f1a8f8-1111-4c1f-9a7e-3b1f2c3d4e5f"}}, t.Name(), info); e != nil {
		t.Fatal(e)
	}
	if e := roundtrip(conn, []byte("after")); e != nil {
		t.Fatalf("removing nobody rebuilt the listener: %v", e)
	}
}

// Activity in either direction keeps a UDP mapping. A flow that only uploads
// used to expire after UDPTimeout and come back from a new source port.
func TestUploadOnlyUDPFlowKeepsItsMapping(t *testing.T) {
	_, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	sink, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	ports := make(chan int, 32)
	go func() {
		b := make([]byte, 128)
		for {
			_, from, e := sink.ReadFrom(b)
			if e != nil {
				return
			}
			ports <- from.(*net.UDPAddr).Port
		}
	}()
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	relay := socksAssociation(t, info, pc)
	// The fixture's UDP idle timeout is two seconds.
	for i := 0; i < 8; i++ {
		socksDatagram(t, pc, relay, sink.LocalAddr().String(), "upload "+strconv.Itoa(i))
		time.Sleep(400 * time.Millisecond)
	}
	seen := map[int]bool{}
	for len(seen) < 2 {
		select {
		case port := <-ports:
			seen[port] = true
		case <-time.After(500 * time.Millisecond):
			if len(seen) != 1 {
				t.Fatalf("sink saw source ports %v", seen)
			}
			return
		}
	}
	t.Fatalf("an active upload-only flow was remapped: source ports %v", seen)
}

// Billing follows InUser. A later request on an authenticated keep-alive
// connection that names another subscriber with a wrong password must be
// refused, not forwarded and billed to that subscriber.
func TestHTTPKeepAliveRequestCannotBorrowAnotherIdentity(t *testing.T) {
	other := panel.UserInfo{Id: 18, Uuid: "5b0c5bb7-3c2f-4d0e-8a44-5f7b9a5f2e11"}
	c, info, _ := fixture(t, "http", []panel.UserInfo{subscriber, other})
	tag := t.Name()
	n, _ := c.get(tag)
	n.limiter.UpdateUser(tag, []panel.UserInfo{subscriber, other}, nil)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer web.Close()
	conn, e := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Common.ServerPort)))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	reader := bufio.NewReader(conn)
	send := func(method, target, user, pass string) *http.Response {
		credential := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		request := method + " " + target + " HTTP/1.1\r\nHost: " + web.Listener.Addr().String() + "\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic " + credential + "\r\n\r\n"
		if _, e := conn.Write([]byte(request)); e != nil {
			t.Fatal(e)
		}
		resp, e := http.ReadResponse(reader, &http.Request{Method: method})
		if e != nil {
			t.Fatal(e)
		}
		if method != http.MethodConnect {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		return resp
	}
	if resp := send(http.MethodGet, web.URL+"/", subscriber.Uuid, subscriber.Uuid); resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request: %s", resp.Status)
	}
	if resp := send(http.MethodConnect, tcpEcho(t), other.Uuid, "wrong"); resp.StatusCode == http.StatusOK {
		_, _ = conn.Write([]byte("billed to another subscriber"))
		time.Sleep(200 * time.Millisecond)
		t.Fatalf("request with failed credentials was forwarded; traffic=%v", func() []panel.UserTraffic { v, _ := c.GetUserTrafficSlice(tag, false); return v }())
	}
}
