package mihomo

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/sudoku/crypto"
)

// sudokuSnellVariants are the managed Sudoku and Snell shapes Irboard can
// render: the node settings and the matching client options.
var sudokuSnellVariants = []struct {
	name     string
	protocol string
	node     func(*panel.MihomoNode)
	client   map[string]any
}{
	{name: "sudoku", protocol: "sudoku"},
	{name: "sudoku-ws-mux", protocol: "sudoku", node: func(m *panel.MihomoNode) { m.HTTPMaskMode = "ws" },
		client: map[string]any{"http-mask": true, "http-mask-mode": "ws", "multiplex": "on"}},
	{name: "sudoku-stream", protocol: "sudoku", node: func(m *panel.MihomoNode) { m.HTTPMaskMode = "stream" },
		client: map[string]any{"http-mask": true, "http-mask-mode": "stream"}},
	{name: "sudoku-raw-entropy", protocol: "sudoku", node: func(m *panel.MihomoNode) {
		off, min, max := false, 5, 20
		m.HTTPMask, m.TableType, m.PaddingMin, m.PaddingMax, m.AEADMethod = &off, "prefer_entropy", &min, &max, "aes-128-gcm"
	}, client: map[string]any{"http-mask": false, "table-type": "prefer_entropy", "padding-min": 5, "padding-max": 20, "aead-method": "aes-128-gcm"}},
	{name: "snell-v4-reuse", protocol: "snell", client: map[string]any{"reuse": true}},
	{name: "snell-v5", protocol: "snell", node: func(m *panel.MihomoNode) { m.Version = 5 }},
}

// boundClient is the variant's client on another loopback address: another
// device of the same subscriber.
func boundClient(t *testing.T, info *panel.NodeInfo, u panel.UserInfo, ip net.IP) connDialer {
	t.Helper()
	basic := outbound.BasicOption{DialerForAPI: boundDialer{ip: ip}}
	var p interface {
		connDialer
		Close() error
	}
	var e error
	switch info.Type {
	case "sudoku":
		master, err := parseSudokuMaster(info.Mihomo.Key)
		if err != nil {
			t.Fatal(err)
		}
		mask := info.Mihomo.HTTPMask == nil || *info.Mihomo.HTTPMask
		p, e = outbound.NewSudoku(outbound.SudokuOption{BasicOption: basic, Name: ip.String(), Server: "127.0.0.1", Port: info.Common.ServerPort,
			Key: master.userKey(u.Uuid), HTTPMask: &mask, HTTPMaskMode: info.Mihomo.HTTPMaskMode, TableType: info.Mihomo.TableType,
			PaddingMin: info.Mihomo.PaddingMin, PaddingMax: info.Mihomo.PaddingMax, AEADMethod: info.Mihomo.AEADMethod})
	case "snell":
		p, e = outbound.NewSnell(outbound.SnellOption{BasicOption: basic, Name: ip.String(), Server: "127.0.0.1", Port: info.Common.ServerPort,
			Psk: u.Uuid, Version: info.Mihomo.Version, UDP: true,
			ObfsOpts: map[string]any{"mode": "shadow-tls", "version": 3, "host": info.Mihomo.ObfsOpts.Host, "password": u.Uuid, "skip-cert-verify": true}})
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// Real mihomo Sudoku and Snell clients against managed nodes, for what the
// panel controls about a subscriber beyond the round trip, ban and live
// membership of TestForkServerRoundTripsAndRevocation and
// TestMembershipChangesKeepOtherUsersConnected.
func TestSudokuAndSnellEndToEnd(t *testing.T) {
	other := panel.UserInfo{Id: 18, Uuid: "5b0c5bb7-3c2f-4d0e-8a44-5f7b9a5f2e11"}
	for _, v := range sudokuSnellVariants {
		v := v
		start := func(t *testing.T, users ...panel.UserInfo) (*Core, *panel.NodeInfo, *node) {
			c, info, _ := fixture(t, v.protocol, nil)
			if v.node != nil {
				v.node(info.Mihomo)
			}
			addUsers(t, c, users...)
			n, _ := c.get(t.Name())
			return c, info, n
		}
		connect := func(t *testing.T, info *panel.NodeInfo, u panel.UserInfo, extra ...map[string]any) C.Proxy {
			return client(t, info, u, append([]map[string]any{v.client}, extra...)...)
		}
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			t.Run("TCP and UDP", func(t *testing.T) {
				c, info, _ := start(t, subscriber)
				p := connect(t, info, subscriber)
				target := tcpEcho(t)
				for i := 0; i < 3; i++ {
					if e := tryRoundtrip(p, target, v.name+" "+strconv.Itoa(i)); e != nil {
						t.Fatal(e)
					}
				}
				s := openUDP(t, p)
				if e := s.roundtrip("datagram"); e != nil {
					t.Fatal(e)
				}
				await(t, func() bool {
					rows, _ := c.GetUserTrafficSlice(t.Name(), false)
					return len(rows) == 1 && rows[0].UID == subscriber.Id && rows[0].Upload == int64(3*len(v.name+" 0")+len("datagram"))
				})
			})
			t.Run("credentials", func(t *testing.T) {
				_, info, _ := start(t, subscriber)
				target := tcpEcho(t)
				wrong := map[string]map[string]any{"unknown user": nil}
				switch v.protocol {
				case "sudoku":
					pair, e := crypto.GenerateMasterKey()
					if e != nil {
						t.Fatal(e)
					}
					foreign, e := crypto.SplitPrivateKey(pair.Private)
					if e != nil {
						t.Fatal(e)
					}
					master, _ := parseSudokuMaster(info.Mihomo.Key)
					wrong["another master's key"] = map[string]any{"key": foreign}
					wrong["the public key"] = map[string]any{"key": master.public}
				case "snell":
					wrong["another PSK"] = map[string]any{"psk": other.Uuid}
					wrong["another ShadowTLS password"] = map[string]any{"obfs-opts": map[string]any{"mode": "shadow-tls", "version": 3, "host": "localhost", "password": other.Uuid, "skip-cert-verify": true}}
				}
				for name, override := range wrong {
					u := subscriber
					if override == nil {
						u = other
					}
					if e := tryRoundtrip(connect(t, info, u, override), target, name); e == nil {
						t.Fatalf("%s: forwarded", name)
					}
				}
				if e := tryRoundtrip(connect(t, info, subscriber), target, "right"); e != nil {
					t.Fatal(e)
				}
			})
			t.Run("speed limit and live upgrade", func(t *testing.T) {
				_, info, n := start(t, subscriber)
				n.limiter.UpdateUserLimits(t.Name(), []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, SpeedLimit: 1}})
				conn := dial(t, connect(t, info, subscriber), tcpEcho(t))
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				payload := bytes.Repeat([]byte{0x5a}, 256*1024)
				begin := time.Now()
				written := make(chan error, 1)
				go func() { _, e := conn.Write(payload); written <- e }()
				if _, e := io.ReadFull(conn, make([]byte, len(payload))); e != nil {
					t.Fatal(e)
				}
				if e := <-written; e != nil {
					t.Fatal(e)
				}
				// Upload and download share the 1 Mbps bucket and its 64 KiB burst.
				if elapsed := time.Since(begin); elapsed < 2700*time.Millisecond || elapsed > 10*time.Second {
					t.Fatalf("a 1 Mbps round trip took %s", elapsed)
				}
				large := bytes.Repeat([]byte{0x6b}, 1024*1024)
				go func() { _, e := conn.Write(large); written <- e }()
				time.AfterFunc(150*time.Millisecond, func() {
					n.limiter.UpdateUserLimits(t.Name(), []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, SpeedLimit: 50}})
				})
				begin = time.Now()
				out := make([]byte, len(large))
				if _, e := io.ReadFull(conn, out); e != nil {
					t.Fatal(e)
				}
				if e := <-written; e != nil {
					t.Fatal(e)
				}
				if elapsed := time.Since(begin); elapsed > 5*time.Second {
					t.Fatalf("the open connection kept the old speed: %s", elapsed)
				}
				if !bytes.Equal(out, large) {
					t.Fatal("payload corrupted")
				}
			})
			t.Run("device limit", func(t *testing.T) {
				_, info, n := start(t, subscriber)
				target := tcpEcho(t)
				first := dial(t, connect(t, info, subscriber), target)
				if e := roundtrip(first, []byte("first device")); e != nil {
					t.Fatal(e)
				}
				if e := tryRoundtrip(boundClient(t, info, subscriber, net.IPv4(127, 0, 0, 3)), target, "no limit yet"); e != nil {
					t.Fatalf("a second device was refused without a device limit: %v", e)
				}
				n.limiter.UpdateUserLimits(t.Name(), []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, DeviceLimit: 1}})
				if tryRoundtrip(boundClient(t, info, subscriber, net.IPv4(127, 0, 0, 2)), target, "over the limit") == nil {
					t.Fatal("a new device was admitted over the device limit")
				}
				_ = first.SetDeadline(time.Now().Add(3 * time.Second))
				if e := roundtrip(first, []byte("first still works")); e != nil {
					t.Fatal(e)
				}
			})
			t.Run("panel rules", func(t *testing.T) {
				_, info, n := start(t, subscriber)
				p := connect(t, info, subscriber)
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

// A prober that speaks HTTP to a Sudoku node finds the node's cover site, as
// on the other cores, instead of a socket that closes.
func TestSudokuProbersFindTheCoverSite(t *testing.T) {
	_, info, _ := fixture(t, "sudoku", []panel.UserInfo{subscriber})
	raw, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Common.ServerPort)), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	if _, e = raw.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe\r\n\r\n")); e != nil {
		t.Fatal(e)
	}
	resp, e := http.ReadResponse(bufio.NewReader(raw), nil)
	if e != nil {
		t.Fatalf("no web site behind the Sudoku port: %v", e)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("cover site answered %s %q", resp.Status, resp.Header.Get("Content-Type"))
	}
	// The subscriber is unaffected.
	if e := tryRoundtrip(client(t, info, subscriber), tcpEcho(t), "after a probe"); e != nil {
		t.Fatal(e)
	}
}

// A stranger's TLS handshake with a Snell node completes with the handshake
// server's certificate: ShadowTLS v3 relays it there in strict mode.
func TestSnellStrangersReachTheHandshakeServer(t *testing.T) {
	_, info, options := fixture(t, "snell", []panel.UserInfo{subscriber})
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Common.ServerPort)),
		&tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
	if e != nil {
		t.Fatalf("a stranger's TLS handshake failed: %v", e)
	}
	defer conn.Close()
	leaf := conn.ConnectionState().PeerCertificates[0]
	pair, _ := tls.LoadX509KeyPair(options.CertConfig.CertFile, options.CertConfig.KeyFile)
	if !bytes.Equal(leaf.Raw, pair.Certificate[0]) {
		t.Fatal("the stranger did not see the handshake server's certificate")
	}
}

// Only the endpoints a node configured can be reached as a listener's own
// connection, and a stranger relayed to one is slowed after innerBudget.
func TestInnerConnectionsReachOnlyConfiguredEndpoints(t *testing.T) {
	c, _, _ := fixture(t, "sudoku", []panel.UserInfo{subscriber})
	n, _ := c.get(t.Name())
	target := tcpEcho(t)
	allowed, e := innerAddress(target)
	if e != nil {
		t.Fatal(e)
	}
	relay := func(inner map[string]bool, payload []byte) (time.Duration, error) {
		local, remote := net.Pipe()
		defer local.Close()
		m := metadata(t, target)
		m.Type = C.INNER
		go (&nodeTunnel{node: n, inner: inner}).HandleTCPConn(remote, m)
		_ = local.SetDeadline(time.Now().Add(10 * time.Second))
		begin := time.Now()
		go func() { _, _ = local.Write(payload) }()
		_, e := io.ReadFull(local, make([]byte, len(payload)))
		return time.Since(begin), e
	}
	if _, e := relay(nil, []byte("not configured")); e == nil {
		t.Fatal("an unconfigured endpoint was reached")
	}
	if _, e := relay(map[string]bool{allowed: true}, []byte("configured")); e != nil {
		t.Fatal(e)
	}

	budget, limit := innerBudget, innerRate
	innerBudget, innerRate = 1<<10, 16<<10
	t.Cleanup(func() { innerBudget, innerRate = budget, limit })
	// 1 KiB free, a 16 KiB burst, then 32 KiB at 16 KiB/s: at least 2 s.
	elapsed, e := relay(map[string]bool{allowed: true}, bytes.Repeat([]byte{1}, 49<<10))
	if e != nil {
		t.Fatal(e)
	}
	if elapsed < 1800*time.Millisecond {
		t.Fatalf("a stranger's relay was not slowed past its budget: %s", elapsed)
	}
}
