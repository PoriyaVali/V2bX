package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
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
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/internal/udpecho"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
)

// ledgerOther is a second user of every node: no client uses it, so no
// traffic may be billed to it.
const (
	ledgerUser  = 2
	ledgerOther = 3
	ledgerUUID3 = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	// servedUUID is the subscriber of served.json: user 2, whose
	// credentials every profile there carries.
	servedUUID = "11111111-2222-3333-4444-555555555555"
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
}

func newLedgerPanel(n servedNode, uids ...int) *ledgerPanel {
	p := &ledgerPanel{n: n, seen: map[string]bool{}, traffic: map[int][2]int64{}}
	p.setUsers(uids...)
	return p
}

// setUsers makes the panel's user list the users with these ids: 2 is the
// subscriber the profiles are for, 3 a user no client uses.
func (p *ledgerPanel) setUsers(uids ...int) {
	var list struct {
		Users []map[string]any `json:"users"`
	}
	list.Users = []map[string]any{}
	for _, uid := range uids {
		uuid := ledgerUUID3
		if uid == ledgerUser {
			uuid = servedUUID
		}
		list.Users = append(list.Users, map[string]any{"id": uid, "uuid": uuid, "speed_limit": 0, "device_limit": 0})
	}
	body, _ := json.Marshal(list)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users = servedResponse{Body: body, ContentType: "application/json", ETag: fmt.Sprintf(`"users-%x"`, body)}
}

// fetched is whether V2bX has fetched the current user list.
func (p *ledgerPanel) fetched() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.served == p.users.ETag
}

func (p *ledgerPanel) billed(uid int) [2]int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.traffic[uid]
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
			if r.Header.Get("If-None-Match") == p.n.Config.ETag && p.n.Config.ETag != "" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
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
			p.mu.Unlock()
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			_, _ = w.Write([]byte(`{"data":true}`))
		}
	})
}

// ledgerConfig is the node's config reporting and polling every second.
func ledgerConfig(t *testing.T, n servedNode) servedNode {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(n.Config.Body, &config); err != nil {
		t.Fatal(err)
	}
	base, _ := config["base_config"].(map[string]any)
	if base == nil {
		base = map[string]any{}
	}
	base["push_interval"], base["pull_interval"] = 1, 1
	config["base_config"] = base
	var err error
	if n.Config.Body, err = json.Marshal(config); err != nil {
		t.Fatal(err)
	}
	n.Config.ETag = ""
	return n
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

// ledgerClient is one client of a node: how it echoes over TCP and UDP, and
// how it holds a connection open across a change on the node.
type ledgerClient struct {
	name string
	// bulk echoes size bytes over a new TCP connection.
	bulk func(size int) error
	// datagrams echoes count datagrams of size bytes over a new UDP session,
	// and returns the bytes sent and answered; nil when the profile has no UDP.
	datagrams func(count, size int) (sent, received int64, err error)
	// hold opens a TCP connection and echoes over it; still echoes over it
	// again and closes it.
	hold func() (still func() error, err error)
}

// ledgerClients are the clients Irboard configures for the node, pointed at
// port.
func ledgerClients(t *testing.T, n servedNode, port int, cert servedCert, echo string, udp netip.AddrPort, mihomo string) []ledgerClient {
	t.Helper()
	var clients []ledgerClient
	if n.Clash != nil {
		profile := clashProfile(t, n.Clash, port)
		clients = append(clients, ledgerClient{
			name: "mihomo",
			bulk: func(size int) error { return runClash(t, mihomo, profile, echo, "bulk", strconv.Itoa(size)) },
			datagrams: func(count, size int) (int64, int64, error) {
				out, err := exec.Command(mihomo, profile, udp.String(), "udp-bulk", strconv.Itoa(count), strconv.Itoa(size)).CombinedOutput()
				var sent, received int64
				if _, scan := fmt.Sscanf(strings.TrimSpace(string(out)), "ok sent=%d received=%d", &sent, &received); scan != nil {
					if strings.Contains(string(out), udpecho.ErrNoUDP.Error()) {
						return 0, 0, udpecho.ErrNoUDP
					}
					return 0, 0, fmt.Errorf("%s (%v)", strings.TrimSpace(string(out)), err)
				}
				return sent, received, nil
			},
			hold: func() (func() error, error) { return holdClash(mihomo, profile, echo) },
		})
	}
	if n.Singbox != nil {
		client, socks, err := singboxClient(t, n.Singbox, port)
		if err != nil {
			t.Logf("sing-box client: %v", err)
		} else {
			clients = append(clients, ledgerClient{
				name: "sing-box",
				bulk: func(size int) error {
					conn, err := socksConnect(socks, echo)
					if err != nil {
						return err
					}
					defer conn.Close()
					return bulk(conn, size)
				},
				datagrams: func(count, size int) (int64, int64, error) {
					pc, err := singboxPacketConn(client, udp)
					if err != nil {
						return 0, 0, err
					}
					return udpecho.Bulk(pc, udp, count, size)
				},
				hold: func() (func() error, error) {
					return holdConn(func() (net.Conn, error) { return socksConnect(socks, echo) })
				},
			})
		}
	}
	if inst, err := xrayClient(n.Link, port, cert.sha256); err == nil {
		t.Cleanup(func() { _ = inst.Close() })
		clients = append(clients, ledgerClient{
			name: "xray",
			bulk: func(size int) error {
				conn, err := xrayConn(inst, echo)
				if err != nil {
					return err
				}
				defer conn.Close()
				return bulk(conn, size)
			},
			datagrams: func(count, size int) (int64, int64, error) {
				pc, err := xcore.DialUDP(context.Background(), inst)
				if err != nil {
					return 0, 0, err
				}
				return udpecho.Bulk(pc, udp, count, size)
			},
			hold: func() (func() error, error) {
				return holdConn(func() (net.Conn, error) { return xrayConn(inst, echo) })
			},
		})
	} else if !errors.Is(err, errNotAnXrayLink) {
		t.Logf("xray client: %v", err)
	}
	return clients
}

// holdConn opens a connection with dial and echoes over it.
func holdConn(dial func() (net.Conn, error)) (func() error, error) {
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	if err := echoes(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return func() error { defer conn.Close(); return echoes(conn) }, nil
}

// holdClash holds a connection open in a mihomo client.
func holdClash(client, profile, echo string) (func() error, error) {
	cmd := exec.Command(client, profile, echo, "hold")
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
}

// TestIrboardServedNodesLedgerSurvey reports, for every node on every core,
// what V2bX bills for known TCP and UDP transfers through every client,
// whether a user the panel drops is cut off and a user it adds back gets in
// again, and the speed a user with a limit gets. Set LEDGER_SURVEY=1 to run
// it; LEDGER_ONLY=NAME runs one node.
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
	echo, udp := servedEcho(t), servedUDPEchoes(t)
	mihomo := buildMihomoClient(t)
	const size, datagrams, datagramSize = 64 << 10, 16, 1000
	for _, name := range names {
		n := ledgerConfig(t, served.Nodes[name])
		info := servedNodeInfo(t, n)
		for _, core := range servedCores {
			if validateSetupCore(core, info) != nil {
				continue
			}
			t.Run(name+"/"+core, func(t *testing.T) {
				p := newLedgerPanel(n, ledgerUser, ledgerOther)
				port, err := startServedNodeWith(t, n, core, cert, p.handler)
				if notInThisBuild(err) {
					t.Skip(err)
				}
				if err != nil {
					t.Fatalf("the node did not start: %v", err)
				}
				clients := ledgerClients(t, n, port, cert, echo, udp[0], mihomo)
				var up, down int64
				var notes []string
				for _, c := range clients {
					if err := c.bulk(size); err != nil {
						notes = append(notes, c.name+" tcp: "+err.Error())
					} else {
						up, down = up+size, down+size
					}
					sent, received, err := c.datagrams(datagrams, datagramSize)
					up, down = up+sent, down+received
					if err != nil && !errors.Is(err, udpecho.ErrNoUDP) {
						notes = append(notes, c.name+" udp: "+err.Error())
					}
				}
				waitBilled(p, up, down)
				billed, other := p.billed(ledgerUser), p.billed(ledgerOther)

				var holds []func() error
				var held []string
				for _, c := range clients {
					if still, err := c.hold(); err == nil {
						holds, held = append(holds, still), append(held, c.name)
					} else {
						notes = append(notes, c.name+" hold: "+err.Error())
					}
				}
				p.setUsers(ledgerOther)
				waitFetched(p)
				var stillOpen, letIn []string
				for i, still := range holds {
					if still() == nil {
						stillOpen = append(stillOpen, held[i])
					}
				}
				for _, c := range clients {
					if c.bulk(1024) == nil {
						letIn = append(letIn, c.name)
					}
				}
				p.setUsers(ledgerUser, ledgerOther)
				waitFetched(p)
				var keptOut []string
				for _, c := range clients {
					if err := c.bulk(1024); err != nil {
						keptOut = append(keptOut, c.name+": "+err.Error())
					}
				}

				// 2 Mbit/s is 250 kB/s: 512 KiB each way takes two seconds.
				var rate string
				if len(clients) > 0 {
					// A plan's limit changing for a user already on the node.
					p.setUsersLimited(ledgerUser, 2)
					waitFetched(p)
					start := time.Now()
					err := clients[0].bulk(512 << 10)
					took := time.Since(start)
					rate = fmt.Sprintf("%s 512KiB each way at 2Mbps took %v (%v)", clients[0].name, took.Round(10*time.Millisecond), err)
				}
				t.Logf("LEDGER %-34s %-9s up=%d/%d down=%d/%d other=%v | after removal: still open %v, let in %v | re-added, kept out %v | %s | notes %v",
					name, core, billed[0], up, billed[1], down, other, stillOpen, letIn, keptOut, rate, notes)
			})
		}
	}
}

// setUsersLimited makes the subscriber the only user, with a speed limit in
// Mbit/s, as Irboard sends a plan's speed limit.
func (p *ledgerPanel) setUsersLimited(uid, mbps int) {
	body, _ := json.Marshal(map[string]any{"users": []any{map[string]any{"id": uid, "uuid": servedUUID, "speed_limit": mbps, "device_limit": 0}}})
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users = servedResponse{Body: body, ContentType: "application/json", ETag: fmt.Sprintf(`"users-%x"`, body)}
}

// waitBilled waits for V2bX to report at least up and down for the
// subscriber, and a second more for a report still on its way.
func waitBilled(p *ledgerPanel, up, down int64) {
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if b := p.billed(ledgerUser); b[0] >= up && b[1] >= down {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
}

// waitFetched waits for V2bX to fetch the panel's user list, and a second
// and a half more for it to apply it.
func waitFetched(p *ledgerPanel) {
	for i := 0; i < 50 && !p.fetched(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
}
