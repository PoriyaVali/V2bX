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

// ledgerCounts are what was billed to the subscriber, and what the targets
// counted at that moment.
type ledgerCounts struct {
	billedUp, targetUp, billedDown, targetDown int64
}

func (c ledgerCounts) String() string {
	return fmt.Sprintf("up=%d/%d down=%d/%d", c.billedUp, c.targetUp, c.billedDown, c.targetDown)
}

// off is how far the bill is from what the targets counted. A connection's
// last TLS alert may be counted on one side and not the other, 24 bytes a
// time.
func (c ledgerCounts) off() int64 {
	return max(c.billedUp-c.targetUp, c.targetUp-c.billedUp, c.billedDown-c.targetDown, c.targetDown-c.billedDown)
}

// ledgerSpeed is how long one client took to move ledgerLimited bytes each
// way under the limit.
type ledgerSpeed struct {
	client   string
	up, down time.Duration
}

// ledgerResult is what ledgerRun saw of one node on one core.
type ledgerResult struct {
	clients []string
	// first is the bill for TCP, TCP carrying TLS and UDP through every
	// client; late, after traffic the node had not reported when the panel
	// removed the user; end, after everything.
	first, late, end ledgerCounts
	// other is what was billed to the user no client used.
	other [2]int64
	// stillOpen are the connections held across the removal that still
	// carried traffic after it; letIn, the clients that got a new one.
	stillOpen, letIn []string
	// keptOut are the clients that could not connect once the user was back.
	keptOut []string
	speeds  []ledgerSpeed
	// notes are what failed along the way.
	notes []string
}

const (
	ledgerPush         = 3
	ledgerSize         = 64 << 10
	ledgerDatagrams    = 16
	ledgerDatagramSize = 1000
	// 2 Mbit/s is 250 kB/s after a 64 KiB burst: 512 KiB take 1.8 seconds.
	ledgerLimit   = 2
	ledgerLimited = 512 << 10
)

// ledgerRun starts the node on core and takes it through a subscriber's
// life: traffic over TCP, TCP carrying TLS and UDP through every client;
// connections held open; more traffic, then the panel removing the user
// before the node has reported it; the panel adding the user back; and the
// user's plan getting a speed limit while they are on the node.
func ledgerRun(t *testing.T, n servedNode, core string, cert servedCert, mihomo string) (ledgerResult, error) {
	t.Helper()
	var r ledgerResult
	p := newLedgerPanel(n)
	port, err := startServedNodeWith(t, n, core, cert, p.handler)
	if err != nil {
		return r, err
	}
	g := newLedgerTargets(t, cert)
	clients := ledgerClients(t, n, port, cert, g, mihomo)
	note := func(c ledgerClient, what string, err error) {
		if err != nil && !errors.Is(err, udpecho.ErrNoUDP) {
			r.notes = append(r.notes, c.name+" "+what+": "+err.Error())
		}
	}
	counts := func() ledgerCounts {
		billed := p.settled(g, ledgerPush)
		return ledgerCounts{billed[0], g.up.Load(), billed[1], g.down.Load()}
	}
	for _, c := range clients {
		r.clients = append(r.clients, c.name)
		note(c, "tcp", c.bulk(ledgerSize, false))
		note(c, "tls", c.bulk(ledgerSize, true))
		note(c, "udp", c.datagrams(ledgerDatagrams, ledgerDatagramSize))
	}
	r.first = counts()

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
	p.settled(g, ledgerPush)
	// Right after a report, so that the next one comes after the removal.
	p.reported()
	if len(clients) > 0 {
		note(clients[0], "tcp before the removal", clients[0].bulk(ledgerSize, false))
	}
	p.setUsers(0, false)
	p.fetched()
	for i, still := range holds {
		if err := still(); err == nil {
			r.stillOpen = append(r.stillOpen, held[i])
		} else if os.Getenv("LEDGER_WHY") != "" {
			t.Logf("%s's held connection: %v", held[i], err)
		}
	}
	for _, c := range clients {
		if c.bulk(1024, false) == nil {
			r.letIn = append(r.letIn, c.name)
		}
	}
	r.late = counts()

	p.setUsers(0, true)
	p.fetched()
	for _, c := range clients {
		if err := c.bulk(1024, false); err != nil {
			r.keptOut = append(r.keptOut, c.name+": "+err.Error())
		}
	}

	p.setUsers(ledgerLimit, true)
	p.fetched()
	for _, c := range clients {
		up, err := c.upload(ledgerLimited)
		note(c, "limited upload", err)
		down, err := c.download(ledgerLimited)
		note(c, "limited download", err)
		r.speeds = append(r.speeds, ledgerSpeed{c.name, up, down})
	}
	r.end = counts()
	r.other = p.billed(ledgerOther)
	return r, nil
}

func ledgerNodes(t *testing.T) map[string]servedNode {
	t.Helper()
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
	return served.Nodes
}

// TestIrboardServedNodesLedgerSurvey reports what ledgerRun sees of every
// node on every core. Set LEDGER_SURVEY=1 to run it; LEDGER_ONLY=NAME runs
// one node, LEDGER_CORE=NAME one core, and LEDGER_PARALLEL=1 the nodes side
// by side.
func TestIrboardServedNodesLedgerSurvey(t *testing.T) {
	if os.Getenv("LEDGER_SURVEY") == "" {
		t.Skip("LEDGER_SURVEY is not set")
	}
	nodes := ledgerNodes(t)
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		if only := os.Getenv("LEDGER_ONLY"); only == "" || only == name {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	cert := servedCertificate(t)
	mihomo := buildMihomoClient(t)
	for _, name := range names {
		n := ledgerConfig(t, nodes[name], ledgerPush)
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
				r, err := ledgerRun(t, n, core, cert, mihomo)
				if notInThisBuild(err) {
					t.Skip(err)
				}
				if err != nil {
					t.Fatalf("the node did not start: %v", err)
				}
				var speed []string
				for _, s := range r.speeds {
					speed = append(speed, fmt.Sprintf("%s up %.2fs down %.2fs", s.client, s.up.Seconds(), s.down.Seconds()))
				}
				t.Logf("LEDGER %-34s %-9s | billed %v | after a removal %v | at the end %v other=%v | removed: still open %v, let in %v | re-added: kept out %v | 512KiB at 2Mbps: %s | notes %v",
					name, core, r.first, r.late, r.end, r.other, r.stillOpen, r.letIn, r.keptOut, strings.Join(speed, "; "), r.notes)
			})
		}
	}
}

// ledgerCases are a node of each kind the survey found a fault with, on the
// core it was found on, and the Mihomo core's own.
var ledgerCases = []struct{ node, core string }{
	// A removed user kept VLESS connections under Vision and over XHTTP,
	// VLESS uploads were not limited, and no protocol's last traffic before
	// a removal was billed.
	{"vless/tcp-tls-vision", "xray"},
	{"vless/xhttp-tls-padding", "xray"},
	{"trojan/tcp", "xray"},
	// The last traffic before a removal was not billed, and no speed limit
	// applied.
	{"hysteria2/plain", "hysteria2"},
	// A gRPC connection could not be closed: removing its user stalled the
	// node, and the user, added back, was refused.
	{"trojan/grpc", "sing"},
	// The end of a limited download over AnyTLS was delivered and not billed.
	{"anytls/tls", "sing"},
	// A removed user's QUIC connection stayed up, refusing every stream: a
	// client that kept it got nothing once the user was back.
	{"tuic/bbr", "sing"},
	{"hysteria/v1", "sing"},
	{"vless/tcp-tls", "mihomo"},
	{"hysteria2/plain", "mihomo"},
	// The protocols only the Mihomo core serves, with a user of their own
	// kind each: Mieru's, ShadowQUIC's over QUIC, and Sudoku's derived key.
	{"mieru/tcp", "mihomo"},
	{"shadowquic/default", "mihomo"},
	{"sudoku/default", "mihomo"},
}

// TestIrboardServedNodesBillCutOffAndLimit holds each of ledgerCases to what
// a panel relies on a node for:
//
//   - what the subscriber is billed is what went through the node, to the
//     byte but for a closing TLS alert, traffic not yet reported when the
//     panel removes them included, and nothing is billed to anyone else;
//   - once the panel removes them, the connections they hold stop carrying
//     traffic and no client gets a new one;
//   - once the panel adds them back, every client connects again, the ones
//     that stayed up through the removal included;
//   - under a speed limit of 2 Mbit/s neither an upload nor a download of
//     512 KiB, which take 1.8 seconds, finishes in under 1.2.
func TestIrboardServedNodesBillCutOffAndLimit(t *testing.T) {
	nodes := ledgerNodes(t)
	cert := servedCertificate(t)
	mihomo := buildMihomoClient(t)
	for _, c := range ledgerCases {
		served, ok := nodes[c.node]
		if !ok {
			t.Fatalf("served.json has no %s node", c.node)
		}
		n := ledgerConfig(t, served, ledgerPush)
		t.Run(c.node+"/"+c.core, func(t *testing.T) {
			t.Parallel()
			r, err := ledgerRun(t, n, c.core, cert, mihomo)
			if notInThisBuild(err) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatalf("the node did not start: %v", err)
			}
			if len(r.clients) == 0 {
				t.Fatal("no client could be configured for the node")
			}
			for _, note := range r.notes {
				t.Errorf("%s", note)
			}
			const tolerance = 400
			if r.first.off() > tolerance {
				t.Errorf("billed %v: not what went through the node", r.first)
			}
			if r.late.off() > tolerance {
				t.Errorf("billed %v once the user was removed: what they ran up since the last report is missing", r.late)
			}
			if r.end.off() > tolerance {
				t.Errorf("billed %v at the end: not what went through the node", r.end)
			}
			if r.other != [2]int64{} {
				t.Errorf("%v billed to a user who sent nothing", r.other)
			}
			if len(r.stillOpen) > 0 {
				t.Errorf("connections of the removed user still carry traffic: %v", r.stillOpen)
			}
			if len(r.letIn) > 0 {
				t.Errorf("the removed user got new connections: %v", r.letIn)
			}
			if len(r.keptOut) > 0 {
				t.Errorf("added back, the user is still refused: %v", r.keptOut)
			}
			for _, s := range r.speeds {
				if s.up < 1200*time.Millisecond {
					t.Errorf("%s uploaded 512 KiB in %v at 2 Mbit/s: not limited", s.client, s.up.Round(10*time.Millisecond))
				}
				if s.down < 1200*time.Millisecond {
					t.Errorf("%s downloaded 512 KiB in %v at 2 Mbit/s: not limited", s.client, s.down.Round(10*time.Millisecond))
				}
			}
		})
	}
}
