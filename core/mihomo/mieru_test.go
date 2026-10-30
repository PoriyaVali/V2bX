package mihomo

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

// mieruNode starts a Mieru node on transport serving users.
func mieruNode(t *testing.T, transport string, users ...panel.UserInfo) (*Core, *panel.NodeInfo, *node) {
	t.Helper()
	c, info, _ := fixture(t, "mieru", nil)
	info.Mihomo.Transport = transport
	if len(users) > 0 {
		addUsers(t, c, users...)
	}
	n, _ := c.get(t.Name())
	return c, info, n
}

// boundDialer dials from a fixed loopback address, a second device.
type boundDialer struct{ ip net.IP }

func (d boundDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{LocalAddr: &net.TCPAddr{IP: d.ip}}).DialContext(ctx, network, address)
}
func (d boundDialer) ListenPacket(ctx context.Context, network, _ string, _ netip.AddrPort) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, net.JoinHostPort(d.ip.String(), "0"))
}

// A real mihomo Mieru client against the managed server, on both transports,
// for everything the panel controls about a subscriber.
func TestMieruEndToEnd(t *testing.T) {
	other := panel.UserInfo{Id: 18, Uuid: "5b0c5bb7-3c2f-4d0e-8a44-5f7b9a5f2e11"}
	for _, transport := range []string{"TCP", "UDP"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			t.Run("handshake modes and multiplexing", func(t *testing.T) {
				_, info, _ := mieruNode(t, transport, subscriber)
				target, echo := tcpEcho(t), udpEcho(t)
				for _, handshake := range []string{"HANDSHAKE_DEFAULT", "HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT"} {
					for _, multiplexing := range []string{"MULTIPLEXING_DEFAULT", "MULTIPLEXING_OFF", "MULTIPLEXING_HIGH"} {
						p := client(t, info, subscriber, map[string]any{"handshake-mode": handshake, "multiplexing": multiplexing})
						for i := 0; i < 2; i++ {
							if e := tryRoundtrip(p, target, handshake+" "+multiplexing); e != nil {
								t.Fatalf("%s %s TCP: %v", handshake, multiplexing, e)
							}
						}
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						m := metadata(t, echo.String())
						m.NetWork = C.UDP
						pc, e := p.ListenPacketContext(ctx, m)
						cancel()
						if e != nil {
							t.Fatal(e)
						}
						if e := (&udpSession{t: t, pc: pc, echo: echo}).roundtrip(handshake + " " + multiplexing); e != nil {
							t.Fatalf("%s %s UDP: %v", handshake, multiplexing, e)
						}
						_ = pc.Close()
					}
				}
			})
			t.Run("credentials", func(t *testing.T) {
				_, info, _ := mieruNode(t, transport, subscriber)
				target := tcpEcho(t)
				for name, override := range map[string]map[string]any{
					"wrong password": {"password": "not-" + subscriber.Uuid},
					"unknown user":   {"username": other.Uuid, "password": other.Uuid},
				} {
					if e := tryRoundtrip(client(t, info, subscriber, override), target, name); e == nil {
						t.Fatalf("%s: forwarded", name)
					}
				}
			})
			t.Run("traffic, online and offline", func(t *testing.T) {
				c, info, _ := mieruNode(t, transport, subscriber)
				tag := t.Name()
				p := client(t, info, subscriber)
				conn := dial(t, p, tcpEcho(t))
				payload := bytes.Repeat([]byte("mieru accounting "), 61)
				if e := roundtrip(conn, payload); e != nil {
					t.Fatal(e)
				}
				s := openUDP(t, p)
				if e := s.roundtrip(string(payload[:300])); e != nil {
					t.Fatal(e)
				}
				await(t, func() bool {
					v, _ := c.GetUserTrafficSlice(tag, false)
					return len(v) == 1 && v[0].UID == subscriber.Id && v[0].Upload == int64(len(payload)+300) && v[0].Download == int64(len(payload)+300)
				})
				online, _ := c.OnlineDevices(tag)
				if len(online) != 1 || online[0].UID != subscriber.Id || online[0].IP != "127.0.0.1" {
					t.Fatalf("online=%v", online)
				}
				devices, _ := c.GetDeviceTrafficSlice(tag, false)
				if devices[subscriber.Id]["127.0.0.1"] != 2*int64(len(payload)+300) {
					t.Fatalf("device traffic=%v", devices)
				}
				_ = conn.Close()
				_ = s.pc.Close()
				_ = p.Close()
				// The UDP flow ends after UDPTimeout without traffic.
				deadline := time.Now().Add(8 * time.Second)
				for {
					if online, _ := c.OnlineDevices(tag); len(online) == 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("a subscriber who disconnected is still online")
					}
					time.Sleep(50 * time.Millisecond)
				}
				if v, _ := c.GetUserTrafficSlice(tag, true); len(v) != 1 || v[0].Upload != int64(len(payload)+300) {
					t.Fatalf("drained=%v", v)
				}
				if v, _ := c.GetUserTrafficSlice(tag, false); len(v) != 0 {
					t.Fatalf("a drained report repeated: %v", v)
				}
			})
			t.Run("speed limit and live upgrade", func(t *testing.T) {
				_, info, n := mieruNode(t, transport, subscriber)
				n.limiter.UpdateUserLimits(t.Name(), []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, SpeedLimit: 1}})
				conn := dial(t, client(t, info, subscriber), tcpEcho(t))
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				payload := bytes.Repeat([]byte{0x5a}, 256*1024)
				start := time.Now()
				written := make(chan error, 1)
				go func() { _, e := conn.Write(payload); written <- e }()
				out := make([]byte, len(payload))
				if _, e := io.ReadFull(conn, out); e != nil {
					t.Fatal(e)
				}
				if e := <-written; e != nil {
					t.Fatal(e)
				}
				// Upload and download share the 1 Mbps bucket and its 64 KiB burst.
				if elapsed := time.Since(start); elapsed < 2700*time.Millisecond || elapsed > 10*time.Second {
					t.Fatalf("a 1 Mbps round trip took %s", elapsed)
				}
				large := bytes.Repeat([]byte{0x6b}, 1024*1024)
				go func() { _, e := conn.Write(large); written <- e }()
				time.AfterFunc(150*time.Millisecond, func() {
					n.limiter.UpdateUserLimits(t.Name(), []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, SpeedLimit: 50}})
				})
				start = time.Now()
				out = make([]byte, len(large))
				if _, e := io.ReadFull(conn, out); e != nil {
					t.Fatal(e)
				}
				if e := <-written; e != nil {
					t.Fatal(e)
				}
				if elapsed := time.Since(start); elapsed > 5*time.Second {
					t.Fatalf("the open connection kept the old speed: %s", elapsed)
				}
				if !bytes.Equal(out, large) {
					t.Fatal("payload corrupted")
				}
			})
			t.Run("device limit", func(t *testing.T) {
				_, info, n := mieruNode(t, transport, subscriber)
				target := tcpEcho(t)
				// device is a client on another loopback address, another device.
				device := func(ip net.IP) *outbound.Mieru {
					p, e := outbound.NewMieru(outbound.MieruOption{BasicOption: outbound.BasicOption{DialerForAPI: boundDialer{ip: ip}},
						Name: ip.String(), Server: "127.0.0.1", Port: info.Common.ServerPort, Transport: transport, UserName: subscriber.Uuid, Password: subscriber.Uuid, UDP: true})
					if e != nil {
						t.Fatal(e)
					}
					t.Cleanup(func() { _ = p.Close() })
					return p
				}
				first := dial(t, client(t, info, subscriber), target)
				if e := roundtrip(first, []byte("first device")); e != nil {
					t.Fatal(e)
				}
				if e := tryRoundtrip(device(net.IPv4(127, 0, 0, 3)), target, "no limit yet"); e != nil {
					t.Fatalf("a second device was refused without a device limit: %v", e)
				}
				n.limiter.UpdateUserLimits(t.Name(), []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, DeviceLimit: 1}})
				if tryRoundtrip(device(net.IPv4(127, 0, 0, 2)), target, "over the limit") == nil {
					t.Fatal("a new device was admitted over the device limit")
				}
				_ = first.SetDeadline(time.Now().Add(3 * time.Second))
				if e := roundtrip(first, []byte("first still works")); e != nil {
					t.Fatal(e)
				}
			})
			t.Run("ban and expiry", func(t *testing.T) {
				c, info, _ := mieruNode(t, transport, subscriber, other)
				tag := t.Name()
				target := tcpEcho(t)
				p, q := client(t, info, subscriber), client(t, info, other)
				conn, stays := dial(t, p, target), dial(t, q, target)
				if e := roundtrip(conn, []byte("before ban")); e != nil {
					t.Fatal(e)
				}
				s := openUDP(t, p)
				if e := s.roundtrip("datagram before ban"); e != nil {
					t.Fatal(e)
				}
				delUsers(t, c, info, subscriber)
				_ = stays.SetDeadline(time.Now().Add(3 * time.Second))
				if e := roundtrip(stays, []byte("another subscriber")); e != nil {
					t.Fatalf("a ban disconnected another subscriber: %v", e)
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if roundtrip(conn, []byte("banned")) == nil {
					t.Fatal("a banned subscriber's connection still forwards")
				}
				if s.roundtrip("banned datagram") == nil {
					t.Fatal("a banned subscriber's UDP association still forwards")
				}
				if tryRoundtrip(p, target, "banned") == nil {
					t.Fatal("a banned subscriber opened a new connection")
				}
				_ = stays.SetDeadline(time.Now().Add(3 * time.Second))
				if e := roundtrip(stays, []byte("still there")); e != nil {
					t.Fatalf("a ban disconnected another subscriber: %v", e)
				}
				// The traffic before the ban is still reported.
				v, _ := c.GetUserTrafficSlice(tag, false)
				billed := map[int]int64{}
				for _, row := range v {
					billed[row.UID] = row.Upload
				}
				if billed[subscriber.Id] != int64(len("before ban")+len("datagram before ban")) {
					t.Fatalf("traffic=%v", v)
				}
				// Expiry of the last subscriber closes the port; renewal opens it.
				delUsers(t, c, info, other)
				if raw, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Common.ServerPort)), 200*time.Millisecond); e == nil && transport == "TCP" {
					_ = raw.Close()
					t.Fatal("a node without subscribers kept its port open")
				}
				addUsers(t, c, subscriber)
				if e := tryRoundtrip(client(t, info, subscriber), target, "renewed"); e != nil {
					t.Fatalf("a renewed subscriber cannot connect: %v", e)
				}
			})
			t.Run("traffic pattern", func(t *testing.T) {
				c, info, _ := fixture(t, "mieru", nil)
				info.Mihomo.Transport = transport
				// seed 1, TCP fragments with up to 10 ms between them.
				info.Mihomo.TrafficPattern = "CAEaBAgBEAo="
				addUsers(t, c, subscriber)
				p := client(t, info, subscriber, map[string]any{"traffic-pattern": "CAEaBAgBEAo="})
				if e := tryRoundtrip(p, tcpEcho(t), "patterned"); e != nil {
					t.Fatal(e)
				}
			})
			t.Run("panel rules", func(t *testing.T) {
				_, info, n := mieruNode(t, transport, subscriber)
				p := client(t, info, subscriber)
				target := tcpEcho(t)
				_, port, _ := net.SplitHostPort(target)
				torrent := string(append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...))
				for name, rule := range map[string]*panel.Rules{
					"port rule":                {Port: []string{port}},
					"protocol rule bittorrent": {Protocol: []string{"bittorrent"}},
				} {
					if e := n.limiter.UpdateRule(rule); e != nil {
						t.Fatal(e)
					}
					if tryRoundtrip(p, target, torrent) == nil {
						t.Errorf("%s: forwarded", name)
					}
				}
				if e := n.limiter.UpdateRule(&panel.Rules{}); e != nil {
					t.Fatal(e)
				}
				if e := tryRoundtrip(p, target, torrent); e != nil {
					t.Fatal(e)
				}
			})
		})
	}
}
