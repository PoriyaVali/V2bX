package cmd

// What a node bills, whom it cuts off and how fast it lets a user go, for
// every node Irboard's admin forms make, on every V2bX core that serves it,
// through every client Irboard configures.
//
// A node runs behind ledgerPanel, which answers V2bX as Irboard does, keeps
// the traffic V2bX reports and changes its user list while the node runs. The
// clients reach ledgerTargets through the node: servers that count the bytes
// the node sends them and gets back, which is what the node should bill.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/internal/tcpmeter"
	"github.com/PoriyaVali/V2bX/internal/udpecho"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
)

const (
	// servedUUID is the subscriber of served.json: user 2, whose
	// credentials every profile there carries.
	servedUUID = "11111111-2222-3333-4444-555555555555"
	ledgerUser = 2
	// ledgerOther is a second user of every node. No client uses it, so
	// nothing may be billed to it.
	ledgerOther     = 3
	ledgerOtherUUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

// ledgerPanel answers V2bX as Irboard does, and keeps what V2bX reports: the
// traffic of each user, counting a report id once, as Irboard does. Its user
// list can be changed while the node runs.
type ledgerPanel struct {
	n      servedNode
	config []byte

	mu      sync.Mutex
	users   servedResponse
	served  string // the ETag of the user list V2bX last fetched
	seen    map[string]bool
	traffic map[int][2]int64
	pushes  int // the traffic reports received, empty ones included
}

func newLedgerPanel(n servedNode) *ledgerPanel {
	p := &ledgerPanel{n: n, seen: map[string]bool{}, traffic: map[int][2]int64{}}
	p.setUsers(0, true)
	return p
}

// setUsers makes the panel's user list ledgerOther and, with subscriber, the
// subscriber the profiles are for, at a speed limit of mbps (0 for none), as
// Irboard sends a plan's limit.
func (p *ledgerPanel) setUsers(mbps int, subscriber bool) {
	users := []map[string]any{{"id": ledgerOther, "uuid": ledgerOtherUUID, "speed_limit": 0, "device_limit": 0}}
	if subscriber {
		users = append(users, map[string]any{"id": ledgerUser, "uuid": servedUUID, "speed_limit": mbps, "device_limit": 0})
	}
	body, _ := json.Marshal(map[string]any{"users": users})
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users = servedResponse{Body: body, ContentType: "application/json", ETag: fmt.Sprintf(`"users-%x"`, body)}
}

// fetched waits for V2bX to fetch the panel's user list, and a second more
// for it to apply it.
func (p *ledgerPanel) fetched() {
	for i := 0; i < 80; i++ {
		p.mu.Lock()
		done := p.served == p.users.ETag
		p.mu.Unlock()
		if done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(time.Second)
}

func (p *ledgerPanel) billed(uid int) [2]int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.traffic[uid]
}

// reported waits for V2bX's next traffic report, which it sends every push
// interval, traffic or none.
func (p *ledgerPanel) reported() {
	p.mu.Lock()
	start := p.pushes
	p.mu.Unlock()
	for i := 0; i < 200; i++ {
		p.mu.Lock()
		now := p.pushes
		p.mu.Unlock()
		if now != start {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (p *ledgerPanel) handler(config []byte) http.Handler {
	p.config = config
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "contract-token" {
			http.Error(w, "token", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			_, _ = w.Write(p.config)
		case "/api/v1/server/UniProxy/user":
			p.mu.Lock()
			u := p.users
			p.served = u.ETag
			p.mu.Unlock()
			if r.Header.Get("If-None-Match") == u.ETag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", u.ContentType)
			w.Header().Set("ETag", u.ETag)
			_, _ = w.Write(u.Body)
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		case "/api/v1/server/UniProxy/push":
			var report map[string][2]int64
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			id := r.Header.Get("X-Report-Id")
			p.mu.Lock()
			if id == "" || !p.seen[id] {
				p.seen[id] = true
				for k, v := range report {
					uid, _ := strconv.Atoi(k)
					total := p.traffic[uid]
					total[0] += v[0]
					total[1] += v[1]
					p.traffic[uid] = total
				}
			}
			p.pushes++
			p.mu.Unlock()
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			_, _ = w.Write([]byte(`{"data":true}`))
		}
	})
}

// ledgerConfig is the node's config reporting every push seconds and polling
// every second.
func ledgerConfig(t *testing.T, n servedNode, push int) servedNode {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(n.Config.Body, &config); err != nil {
		t.Fatal(err)
	}
	base, _ := config["base_config"].(map[string]any)
	if base == nil {
		base = map[string]any{}
	}
	base["push_interval"], base["pull_interval"] = push, 1
	config["base_config"] = base
	var err error
	if n.Config.Body, err = json.Marshal(config); err != nil {
		t.Fatal(err)
	}
	n.Config.ETag = ""
	return n
}

// ledgerTargets are the servers a node's clients reach through it. They count
// what the node sends them and what they send back, TLS records and all: the
// upload and the download the node should bill.
type ledgerTargets struct {
	echo, tlsEcho, meter string
	udp                  netip.AddrPort
	up, down             atomic.Int64
}

type countedConn struct {
	net.Conn
	up, down *atomic.Int64
}

func (c countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.up.Add(int64(n))
	return n, err
}

func (c countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.down.Add(int64(n))
	return n, err
}

func newLedgerTargets(t *testing.T, cert servedCert) *ledgerTargets {
	t.Helper()
	g := &ledgerTargets{}
	serve := func(handle func(net.Conn)) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go handle(countedConn{c, &g.up, &g.down})
			}
		}()
		return ln.Addr().String()
	}
	g.echo = serve(func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) })
	pair, err := tls.LoadX509KeyPair(cert.file, cert.key)
	if err != nil {
		t.Fatal(err)
	}
	g.tlsEcho = serve(func(c net.Conn) {
		inner := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{pair}})
		defer inner.Close()
		_, _ = io.Copy(inner, inner)
	})
	g.meter = serve(func(c net.Conn) { _ = tcpmeter.Serve(c) })

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			g.up.Add(int64(n))
			if w, err := pc.WriteToUDPAddrPort(buf[:n], from); err == nil {
				g.down.Add(int64(w))
			}
		}
	}()
	g.udp = pc.LocalAddr().(*net.UDPAddr).AddrPort()
	return g
}

// bulk writes size random bytes through conn and wants them all back. It
// closes conn if they are not back in 20 seconds: an Xray client's connection
// does not honour deadlines.
func bulk(conn net.Conn, size int) error {
	data := make([]byte, size)
	_, _ = rand.Read(data)
	done := make(chan error, 2)
	go func() {
		_, err := conn.Write(data)
		done <- err
	}()
	go func() {
		got := make([]byte, size)
		if _, err := io.ReadFull(conn, got); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, data) {
			done <- errors.New("echoed different bytes")
			return
		}
		done <- nil
	}()
	timeout := time.After(20 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				_ = conn.Close()
				return err
			}
		case <-timeout:
			_ = conn.Close()
			return errors.New("nothing came back in 20 seconds")
		}
	}
	return nil
}

// xrayConn connects through the Xray client to target. The connection lives
// as long as the context it was dialled with, so the context ends with it.
func xrayConn(inst *xcore.Instance, target string) (net.Conn, error) {
	host, ps, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(ps)
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := xcore.Dial(ctx, inst, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	if err != nil {
		cancel()
		return nil, err
	}
	return cancelConnOnClose{conn, cancel}, nil
}

type cancelConnOnClose struct {
	net.Conn
	cancel context.CancelFunc
}

func (c cancelConnOnClose) Close() error {
	defer c.cancel()
	return c.Conn.Close()
}

// ledgerClient is one client of a node.
type ledgerClient struct {
	name string
	// bulk echoes size bytes over a new TCP connection: as they are, or
	// inside TLS to the target, as a browser's traffic is.
	bulk func(size int, innerTLS bool) error
	// upload and download move size bytes one way over a new connection, and
	// return how long it took.
	upload, download func(size int) (time.Duration, error)
	// datagrams echoes count datagrams of size bytes over a new UDP session.
	datagrams func(count, size int) error
	// hold opens a TCP connection and echoes over it; still echoes over it
	// again and closes it.
	hold func(innerTLS bool) (still func() error, err error)
}

// innerTLS speaks TLS to the target over conn, trusting any certificate.
func innerTLS(conn net.Conn) (net.Conn, error) {
	inner := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	done := make(chan error, 1)
	go func() { done <- inner.Handshake() }()
	select {
	case err := <-done:
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("inner TLS: %w", err)
		}
		return inner, nil
	case <-time.After(10 * time.Second):
		conn.Close()
		return nil, errors.New("inner TLS: no handshake in 10 seconds")
	}
}

// connClient is a client that gives connections in this process.
func connClient(name string, g *ledgerTargets, dial func(target string) (net.Conn, error), packets func() (net.PacketConn, error)) ledgerClient {
	open := func(inner bool) (net.Conn, error) {
		if !inner {
			return dial(g.echo)
		}
		conn, err := dial(g.tlsEcho)
		if err != nil {
			return nil, err
		}
		return innerTLS(conn)
	}
	metered := func(move func(net.Conn, int) (time.Duration, error)) func(int) (time.Duration, error) {
		return func(size int) (time.Duration, error) {
			conn, err := dial(g.meter)
			if err != nil {
				return 0, err
			}
			defer conn.Close()
			watchdog := time.AfterFunc(30*time.Second, func() { conn.Close() })
			defer watchdog.Stop()
			return move(conn, size)
		}
	}
	return ledgerClient{
		name: name,
		bulk: func(size int, inner bool) error {
			conn, err := open(inner)
			if err != nil {
				return err
			}
			defer conn.Close()
			return bulk(conn, size)
		},
		upload:   metered(tcpmeter.Upload),
		download: metered(tcpmeter.Download),
		datagrams: func(count, size int) error {
			pc, err := packets()
			if err != nil {
				return err
			}
			_, _, err = udpecho.Bulk(pc, g.udp, count, size)
			return err
		},
		hold: func(inner bool) (func() error, error) {
			conn, err := open(inner)
			if err != nil {
				return nil, err
			}
			if err := echoes(conn); err != nil {
				conn.Close()
				return nil, err
			}
			return func() error { defer conn.Close(); return echoes(conn) }, nil
		},
	}
}

// clashClient is the mihomo client, a program of its own.
func clashClient(program, profile string, g *ledgerTargets) ledgerClient {
	run := func(inner bool, args ...string) (string, error) {
		cmd := exec.Command(program, append([]string{profile}, args...)...)
		if inner {
			cmd.Env = append(os.Environ(), "MIHOMOCLIENT_INNER_TLS=1")
		}
		out, err := cmd.CombinedOutput()
		result := strings.TrimSpace(string(out))
		if err != nil {
			return result, errors.New(result)
		}
		return result, nil
	}
	target := func(inner bool) string {
		if inner {
			return g.tlsEcho
		}
		return g.echo
	}
	metered := func(mode string) func(int) (time.Duration, error) {
		return func(size int) (time.Duration, error) {
			out, err := run(false, g.meter, mode, strconv.Itoa(size))
			if err != nil {
				return 0, err
			}
			var ms int64
			if _, err := fmt.Sscanf(out, "ok ms=%d", &ms); err != nil {
				return 0, errors.New(out)
			}
			return time.Duration(ms) * time.Millisecond, nil
		}
	}
	return ledgerClient{
		name: "mihomo",
		bulk: func(size int, inner bool) error {
			_, err := run(inner, target(inner), "bulk", strconv.Itoa(size))
			return err
		},
		upload:   metered("upload"),
		download: metered("download"),
		datagrams: func(count, size int) error {
			out, err := run(false, g.udp.String(), "udp-bulk", strconv.Itoa(count), strconv.Itoa(size))
			if err != nil && strings.Contains(out, udpecho.ErrNoUDP.Error()) {
				return udpecho.ErrNoUDP
			}
			return err
		},
		hold: func(inner bool) (func() error, error) {
			cmd := exec.Command(program, profile, target(inner), "hold")
			if inner {
				cmd.Env = append(os.Environ(), "MIHOMOCLIENT_INNER_TLS=1")
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				return nil, err
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return nil, err
			}
			cmd.Stderr = cmd.Stdout
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			lines := bufio.NewScanner(stdout)
			if !lines.Scan() || lines.Text() != "ready" {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return nil, fmt.Errorf("mihomo did not hold a connection: %s", lines.Text())
			}
			return func() error {
				defer func() { _ = cmd.Wait() }()
				_, _ = io.WriteString(stdin, "\n")
				if !lines.Scan() {
					return errors.New("mihomo said nothing")
				}
				if lines.Text() != "open" {
					return errors.New(lines.Text())
				}
				return nil
			}, nil
		},
	}
}

// ledgerClients are the clients Irboard configures for the node, pointed at
// port.
func ledgerClients(t *testing.T, n servedNode, port int, cert servedCert, g *ledgerTargets, mihomo string) []ledgerClient {
	t.Helper()
	var clients []ledgerClient
	if n.Clash != nil {
		clients = append(clients, clashClient(mihomo, clashProfile(t, n.Clash, port), g))
	}
	if n.Singbox != nil {
		client, socks, err := singboxClient(t, n.Singbox, port)
		if err != nil {
			t.Logf("sing-box client: %v", err)
		} else {
			clients = append(clients, connClient("sing-box", g,
				func(target string) (net.Conn, error) { return socksConnect(socks, target) },
				func() (net.PacketConn, error) { return singboxPacketConn(client, g.udp) }))
		}
	}
	if inst, err := xrayClient(n.Link, port, cert.sha256); err == nil {
		t.Cleanup(func() { _ = inst.Close() })
		clients = append(clients, connClient("xray", g,
			func(target string) (net.Conn, error) { return xrayConn(inst, target) },
			func() (net.PacketConn, error) { return xcore.DialUDP(context.Background(), inst) }))
	} else if !errors.Is(err, errNotAnXrayLink) {
		t.Logf("xray client: %v", err)
	}
	return clients
}

// settled waits for V2bX to report what the targets counted, for up to three
// push intervals of push seconds, and returns what is billed to the
// subscriber then.
func (p *ledgerPanel) settled(g *ledgerTargets, push int) [2]int64 {
	deadline := time.Now().Add(time.Duration(3*push)*time.Second + time.Second)
	for time.Now().Before(deadline) {
		if b := p.billed(ledgerUser); b[0] >= g.up.Load() && b[1] >= g.down.Load() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return p.billed(ledgerUser)
}

// TestIrboardServedNodesLedgerSurvey reports, for every node on every core,
// with every client:
//
//   - what V2bX bills for TCP, TCP carrying TLS, and UDP, against what the
//     targets counted;
//   - whether what a user ran up since the last report is still billed when
//     the panel removes them;
//   - whether connections held open across the removal still work, and
//     whether new ones get in;
//   - whether the user gets in again once the panel adds them back;
//   - how long an upload and a download take once the user's plan gets a
//     speed limit of 2 Mbit/s, under which 512 KiB takes 1.8 seconds.
//
// Set LEDGER_SURVEY=1 to run it; LEDGER_ONLY=NAME runs one node,
// LEDGER_CORE=NAME one core, and LEDGER_PARALLEL=1 the nodes side by side.
func TestIrboardServedNodesLedgerSurvey(t *testing.T) {
	if os.Getenv("LEDGER_SURVEY") == "" {
		t.Skip("LEDGER_SURVEY is not set")
	}
	raw, err := os.ReadFile("../api/panel/testdata/irboard/served.json")
	if err != nil {
		t.Fatal(err)
	}
	var served struct {
		Nodes map[string]servedNode `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &served); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(served.Nodes))
	for name := range served.Nodes {
		if only := os.Getenv("LEDGER_ONLY"); only == "" || only == name {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	cert := servedCertificate(t)
	mihomo := buildMihomoClient(t)
	const (
		push         = 3
		size         = 64 << 10
		datagrams    = 16
		datagramSize = 1000
		limited      = 512 << 10
	)
	for _, name := range names {
		n := ledgerConfig(t, served.Nodes[name], push)
		info := servedNodeInfo(t, n)
		for _, core := range servedCores {
			if validateSetupCore(core, info) != nil {
				continue
			}
			if only := os.Getenv("LEDGER_CORE"); only != "" && only != core {
				continue
			}
			t.Run(name+"/"+core, func(t *testing.T) {
				if os.Getenv("LEDGER_PARALLEL") != "" {
					t.Parallel()
				}
				p := newLedgerPanel(n)
				port, err := startServedNodeWith(t, n, core, cert, p.handler)
				if notInThisBuild(err) {
					t.Skip(err)
				}
				if err != nil {
					t.Fatalf("the node did not start: %v", err)
				}
				g := newLedgerTargets(t, cert)
				clients := ledgerClients(t, n, port, cert, g, mihomo)
				var notes []string
				note := func(c ledgerClient, what string, err error) {
					if err != nil && !errors.Is(err, udpecho.ErrNoUDP) {
						notes = append(notes, c.name+" "+what+": "+err.Error())
					}
				}

				for _, c := range clients {
					note(c, "tcp", c.bulk(size, false))
					note(c, "tls", c.bulk(size, true))
					note(c, "udp", c.datagrams(datagrams, datagramSize))
				}
				billed := p.settled(g, push)
				first := fmt.Sprintf("up=%d/%d down=%d/%d", billed[0], g.up.Load(), billed[1], g.down.Load())

				// Held connections, then traffic the node has not reported
				// yet when the panel drops the user.
				var holds []func() error
				var held []string
				for _, c := range clients {
					for _, inner := range []bool{false, true} {
						still, err := c.hold(inner)
						if err != nil {
							note(c, "hold", err)
							continue
						}
						holds = append(holds, still)
						held = append(held, map[bool]string{false: c.name, true: c.name + "+tls"}[inner])
					}
				}
				p.settled(g, push)
				p.reported()
				if len(clients) > 0 {
					note(clients[0], "tcp before the removal", clients[0].bulk(size, false))
				}
				p.setUsers(0, false)
				p.fetched()
				var stillOpen, letIn []string
				for i, still := range holds {
					if err := still(); err == nil {
						stillOpen = append(stillOpen, held[i])
					} else if os.Getenv("LEDGER_WHY") != "" {
						t.Logf("%s's held connection: %v", held[i], err)
					}
				}
				for _, c := range clients {
					if c.bulk(1024, false) == nil {
						letIn = append(letIn, c.name)
					}
				}
				billed = p.settled(g, push)
				late := fmt.Sprintf("up=%d/%d down=%d/%d", billed[0], g.up.Load(), billed[1], g.down.Load())

				p.setUsers(0, true)
				p.fetched()
				var keptOut []string
				for _, c := range clients {
					if err := c.bulk(1024, false); err != nil {
						keptOut = append(keptOut, c.name+": "+err.Error())
					}
				}

				// A plan's limit changing for a user already on the node.
				var speed []string
				p.setUsers(2, true)
				p.fetched()
				for _, c := range clients {
					up, err := c.upload(limited)
					note(c, "limited upload", err)
					down, err := c.download(limited)
					note(c, "limited download", err)
					speed = append(speed, fmt.Sprintf("%s up %.2fs down %.2fs", c.name, up.Seconds(), down.Seconds()))
				}
				billed = p.settled(g, push)
				other := p.billed(ledgerOther)
				t.Logf("LEDGER %-34s %-9s | billed %s | after a removal %s | at the end up=%d/%d down=%d/%d other=%v | removed: still open %v, let in %v | re-added: kept out %v | 512KiB at 2Mbps: %s | notes %v",
					name, core, first, late, billed[0], g.up.Load(), billed[1], g.down.Load(), other, stillOpen, letIn, keptOut, strings.Join(speed, "; "), notes)
			})
		}
	}
}
