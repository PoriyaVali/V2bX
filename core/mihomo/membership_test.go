package mihomo

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
	C "github.com/metacubex/mihomo/constant"
)

// addUsers and delUsers change membership as the node controller does: the
// core first, then the limiter.
func addUsers(t *testing.T, c *Core, users ...panel.UserInfo) {
	t.Helper()
	if _, e := c.AddUsers(&vCore.AddUsersParams{Tag: t.Name(), Users: users}); e != nil {
		t.Fatal(e)
	}
	n, _ := c.get(t.Name())
	n.limiter.UpdateUser(t.Name(), users, nil)
}
func delUsers(t *testing.T, c *Core, info *panel.NodeInfo, users ...panel.UserInfo) {
	t.Helper()
	if e := c.DelUsers(users, t.Name(), info); e != nil {
		t.Fatal(e)
	}
	n, _ := c.get(t.Name())
	n.limiter.UpdateUser(t.Name(), nil, users)
}
func generation(c *Core, tag string) uint64 {
	n, _ := c.get(tag)
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.generation
}

// tryRoundtrip opens a new connection and echoes payload over it.
func tryRoundtrip(p C.Proxy, address, payload string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m := &C.Metadata{}
	if e := m.SetRemoteAddress(address); e != nil {
		return e
	}
	conn, e := p.DialContext(ctx, m)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	return roundtrip(conn, []byte(payload))
}

// udpSession is a UDP association that outlives membership changes.
type udpSession struct {
	t    *testing.T
	pc   C.PacketConn
	echo net.Addr
}

func openUDP(t *testing.T, p C.Proxy) *udpSession {
	t.Helper()
	echo := udpEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	m := metadata(t, echo.String())
	m.NetWork = C.UDP
	pc, e := p.ListenPacketContext(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return &udpSession{t: t, pc: pc, echo: echo}
}
func (s *udpSession) roundtrip(payload string) error {
	_ = s.pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e := s.pc.WriteTo([]byte(payload), s.echo); e != nil {
		return e
	}
	b := make([]byte, len(payload)+64)
	count, _, e := s.pc.ReadFrom(b)
	if e != nil {
		return e
	}
	if string(b[:count]) != payload {
		return net.ErrClosed
	}
	return nil
}

// HTTP, SOCKS, Mieru and ShadowQUIC listeners change users in place: a user
// joining or leaving disconnects nobody else, and the user who leaves loses
// every session and cannot start another.
func TestMembershipChangesKeepOtherUsersConnected(t *testing.T) {
	other := panel.UserInfo{Id: 18, Uuid: "5b0c5bb7-3c2f-4d0e-8a44-5f7b9a5f2e11"}
	joining := panel.UserInfo{Id: 19, Uuid: "0f3c7a5e-8d41-4b2a-9c6e-2a7d1e4b9f30"}
	for _, variant := range []struct{ protocol, transport string }{
		{"http", ""}, {"socks5", ""}, {"mieru", "TCP"}, {"mieru", "UDP"}, {"shadowquic", ""},
	} {
		t.Run(variant.protocol+variant.transport, func(t *testing.T) {
			c, info, _ := fixture(t, variant.protocol, nil)
			if variant.transport != "" {
				info.Mihomo.Transport = variant.transport
			}
			tag := t.Name()
			addUsers(t, c, subscriber, other)
			target := tcpEcho(t)
			stays, leaves := client(t, info, subscriber), client(t, info, other)
			kept, gone := dial(t, stays, target), dial(t, leaves, target)
			if e := roundtrip(kept, []byte("before")); e != nil {
				t.Fatal(e)
			}
			if e := roundtrip(gone, []byte("leaving")); e != nil {
				t.Fatal(e)
			}
			var datagrams *udpSession
			if variant.protocol != "http" {
				datagrams = openUDP(t, stays)
				if e := datagrams.roundtrip("datagram before"); e != nil {
					t.Fatal(e)
				}
			}
			listener := generation(c, tag)

			addUsers(t, c, joining)
			if e := roundtrip(kept, []byte("after join")); e != nil {
				t.Fatalf("a user joining disconnected another: %v", e)
			}
			if e := roundtrip(gone, []byte("after join")); e != nil {
				t.Fatalf("a user joining disconnected another: %v", e)
			}
			if e := tryRoundtrip(client(t, info, joining), target, "joined"); e != nil {
				t.Fatalf("the new user cannot connect: %v", e)
			}

			delUsers(t, c, info, other)
			if e := roundtrip(kept, []byte("after leave")); e != nil {
				t.Fatalf("a user leaving disconnected another: %v", e)
			}
			if datagrams != nil {
				if e := datagrams.roundtrip("datagram after"); e != nil {
					t.Fatalf("a user leaving ended another's UDP session: %v", e)
				}
			}
			if e := tryRoundtrip(stays, target, "new connection"); e != nil {
				t.Fatal(e)
			}
			_ = gone.SetDeadline(time.Now().Add(time.Second))
			if e := roundtrip(gone, []byte("removed")); e == nil {
				t.Fatal("the removed user's connection still forwards")
			}
			if e := tryRoundtrip(leaves, target, "removed"); e == nil {
				t.Fatal("the removed user opened a new connection over its session")
			}
			if e := tryRoundtrip(client(t, info, other), target, "removed"); e == nil {
				t.Fatal("the removed user authenticated again")
			}
			if now := generation(c, tag); now != listener {
				t.Fatalf("membership changes replaced the listener (generation %d -> %d)", listener, now)
			}
			await(t, func() bool {
				online, _ := c.OnlineDevices(tag)
				for _, v := range online {
					if v.UID == other.Id {
						return false
					}
				}
				return len(online) > 0
			})
			// The removed user's traffic is still reported.
			traffic, _ := c.GetUserTrafficSlice(tag, false)
			billed := map[int]int64{}
			for _, v := range traffic {
				billed[v.UID] += v.Upload
			}
			if billed[other.Id] != int64(len("leaving")+len("after join")) {
				t.Fatalf("removed user's upload=%d", billed[other.Id])
			}
		})
	}
}

// A name can return with another password: a credential template without the
// UUID in the username does that when a subscriber's UUID is reset. A session
// that authenticated with the old password must not come back with the name, so
// that change replaces the listener.
func TestReturningNameWithAnotherPasswordEndsItsOldSessions(t *testing.T) {
	rekeyed := panel.UserInfo{Id: subscriber.Id, Uuid: "9d2e6f1a-7b3c-4e5d-8f90-1a2b3c4d5e6f"}
	other := panel.UserInfo{Id: 18, Uuid: "5b0c5bb7-3c2f-4d0e-8a44-5f7b9a5f2e11"}
	name := map[string]any{"username": "u" + strconv.Itoa(subscriber.Id)}
	for _, protocol := range []string{"mieru", "shadowquic"} {
		t.Run(protocol, func(t *testing.T) {
			c, info, _ := fixture(t, protocol, nil)
			info.Mihomo.Username = "u{{user_id}}"
			tag := t.Name()
			addUsers(t, c, subscriber, other)
			target := tcpEcho(t)
			old := client(t, info, subscriber, name)
			if e := tryRoundtrip(old, target, "old password"); e != nil {
				t.Fatal(e)
			}
			listener := generation(c, tag)
			delUsers(t, c, info, subscriber)
			if generation(c, tag) != listener {
				t.Fatal("removing one of two users replaced the listener")
			}
			addUsers(t, c, rekeyed)
			if generation(c, tag) == listener {
				t.Fatal("the name returned with another password on the same listener")
			}
			if e := tryRoundtrip(old, target, "stale session"); e == nil {
				t.Fatal("a session of the old password regained access")
			}
			if e := tryRoundtrip(client(t, info, rekeyed, name), target, "new password"); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// HTTP keep-alive connections keep the identity their first request verified.
func TestReturningNameWithAnotherPasswordEndsHTTPKeepAlive(t *testing.T) {
	rekeyed := panel.UserInfo{Id: subscriber.Id, Uuid: "9d2e6f1a-7b3c-4e5d-8f90-1a2b3c4d5e6f"}
	other := panel.UserInfo{Id: 18, Uuid: "5b0c5bb7-3c2f-4d0e-8a44-5f7b9a5f2e11"}
	c, info, _ := fixture(t, "http", nil)
	info.Mihomo.Username = "u{{user_id}}"
	addUsers(t, c, subscriber, other)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer web.Close()
	conn, e := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Common.ServerPort)))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	reader := bufio.NewReader(conn)
	get := func(header string) (int, error) {
		request := "GET " + web.URL + "/ HTTP/1.1\r\nHost: " + web.Listener.Addr().String() + "\r\nProxy-Connection: keep-alive\r\n" + header + "\r\n"
		if _, e := conn.Write([]byte(request)); e != nil {
			return 0, e
		}
		resp, e := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if e != nil {
			return 0, e
		}
		defer resp.Body.Close()
		_, _ = reader.Discard(reader.Buffered())
		return resp.StatusCode, nil
	}
	credential := base64.StdEncoding.EncodeToString([]byte("u" + strconv.Itoa(subscriber.Id) + ":" + subscriber.Uuid))
	if status, e := get("Proxy-Authorization: Basic " + credential + "\r\n"); e != nil || status != http.StatusOK {
		t.Fatalf("authenticated request: %d %v", status, e)
	}
	if status, e := get(""); e != nil || status != http.StatusOK {
		t.Fatalf("keep-alive request: %d %v", status, e)
	}
	delUsers(t, c, info, subscriber)
	if status, e := get(""); e == nil && status == http.StatusOK {
		t.Fatal("the removed user's keep-alive connection still forwards")
	}
	addUsers(t, c, rekeyed)
	if status, e := get(""); e == nil && status == http.StatusOK {
		t.Fatal("a keep-alive connection of the old password regained access")
	}
}

// The removed credentials a running listener remembers are bounded.
func TestRevokedCredentialsAreBounded(t *testing.T) {
	other := panel.UserInfo{Id: 18, Uuid: "5b0c5bb7-3c2f-4d0e-8a44-5f7b9a5f2e11"}
	c, info, _ := fixture(t, "socks5", nil)
	tag := t.Name()
	addUsers(t, c, subscriber, other)
	n, _ := c.get(tag)
	n.mu.Lock()
	n.revoked = map[string]string{}
	for i := 0; i < maxRevoked; i++ {
		n.revoked["gone"+strconv.Itoa(i)] = "password"
	}
	n.mu.Unlock()
	listener := generation(c, tag)
	delUsers(t, c, info, other)
	if generation(c, tag) == listener {
		t.Fatal("the bound was exceeded on the same listener")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.revoked) != 0 {
		t.Fatalf("a new listener inherited %d revoked credentials", len(n.revoked))
	}
}
