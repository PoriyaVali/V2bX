package smartdns

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// resolver is a DNS server on loopback, UDP and TCP on one port, whose UDP
// answers can be withheld.
type resolver struct {
	addr     string
	udp, tcp atomic.Int64
	// dropUDP says whether the n-th UDP query goes unanswered.
	dropUDP atomic.Pointer[func(n int64) bool]
	// answer builds the answer; nil answers every A question with 192.0.2.1.
	answer func(req *dns.Msg, overUDP bool) *dns.Msg
}

func (r *resolver) drop(f func(n int64) bool) { r.dropUDP.Store(&f) }

func startResolver(t *testing.T, answer ...func(req *dns.Msg, overUDP bool) *dns.Msg) *resolver {
	t.Helper()
	r := &resolver{}
	if len(answer) == 1 {
		r.answer = answer[0]
	}
	r.drop(func(int64) bool { return false })
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = pc.LocalAddr().String()
	ln, err := net.Listen("tcp4", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		overUDP := w.RemoteAddr().Network() == "udp"
		if overUDP {
			if (*r.dropUDP.Load())(r.udp.Add(1)) {
				return
			}
		} else {
			r.tcp.Add(1)
		}
		var resp *dns.Msg
		if r.answer != nil {
			resp = r.answer(req, overUDP)
		} else {
			resp = new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 1),
			})
		}
		_ = w.WriteMsg(resp)
	})
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: ln, Handler: handler}} {
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return r
}

func startService(t *testing.T, mode string, resolvers ...*resolver) *Service {
	t.Helper()
	cfg := Config{Mode: mode}
	for _, r := range resolvers {
		cfg.Servers = append(cfg.Servers, r.addr)
	}
	s, reason, err := Start(cfg)
	if err != nil || s == nil {
		t.Fatalf("the forwarder did not start: %v %s", err, reason)
	}
	t.Cleanup(s.Close)
	return s
}

// ask sends the forwarder an A question over UDP, as a core does.
func ask(t *testing.T, s *Service, name string) (*dns.Msg, time.Duration) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	q.SetEdns0(1232, false)
	c := dns.Client{Timeout: 6 * time.Second}
	resp, took, err := c.Exchange(q, s.Addr().String())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return resp, took
}

func TestAnswersAreKeptForTheirTTL(t *testing.T) {
	up := startResolver(t)
	s := startService(t, ModeAuto, up)
	first, _ := ask(t, s, "kept.example")
	if first.Rcode != dns.RcodeSuccess || len(first.Answer) != 1 {
		t.Fatalf("answer %v", first)
	}
	for range 5 {
		again, _ := ask(t, s, "KEPT.example")
		if len(again.Answer) != 1 || again.Question[0].Name != "KEPT.example." {
			t.Fatalf("the kept answer: %v", again)
		}
	}
	if n := up.udp.Load() + up.tcp.Load(); n != 1 {
		t.Fatalf("the resolver was asked %d times for one name", n)
	}
	// An expired answer is asked for again.
	s.cache.mu.Lock()
	for k, e := range s.cache.m {
		e.expires = time.Now().Add(-time.Second)
		s.cache.m[k] = e
	}
	s.cache.mu.Unlock()
	ask(t, s, "kept.example")
	if n := up.udp.Load() + up.tcp.Load(); n != 2 {
		t.Fatalf("the resolver was asked %d times, want 2 once the answer expired", n)
	}
}

// The case this exists for: a path that loses about one UDP query in eight.
// Every name is still answered, without waiting out a resolver timeout, the
// forwarder moves to TCP, and it moves back once UDP is answered again.
func TestLossyUDPMovesToTCPAndBack(t *testing.T) {
	up := startResolver(t)
	up.drop(func(n int64) bool { return n%8 == 0 })
	s := startService(t, ModeAuto, up)
	var slowest time.Duration
	for i := 0; !s.OverTCP(); i++ {
		if i == 400 {
			t.Fatal("still on UDP after 400 queries with one in eight lost")
		}
		resp, took := ask(t, s, fmt.Sprintf("lossy-%d.example", i))
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("query %d: %v", i, resp)
		}
		slowest = max(slowest, took)
	}
	if slowest > 1500*time.Millisecond {
		t.Errorf("a query with its UDP packet lost took %v", slowest)
	}
	before := up.tcp.Load()
	for i := range 20 {
		if _, took := ask(t, s, fmt.Sprintf("tcp-%d.example", i)); took > time.Second {
			t.Errorf("a query over TCP took %v", took)
		}
	}
	if got := up.tcp.Load() - before; got != 20 {
		t.Fatalf("%d of 20 queries went over TCP", got)
	}
	// UDP heals: a window of probes, one every probeEvery queries. The
	// queries lost before the move are counted first, as their waits end.
	up.drop(func(int64) bool { return false })
	time.Sleep(udpTimeout + 100*time.Millisecond)
	for i := 0; s.OverTCP(); i++ {
		if i > lossWindow*probeEvery+50 {
			t.Fatal("still on TCP after a full window of answered probes")
		}
		ask(t, s, fmt.Sprintf("healed-%d.example", i))
		// A probe is counted when its answer arrives.
		time.Sleep(time.Millisecond)
	}
}

func TestDeadUDPIsAnsweredOverTCP(t *testing.T) {
	up := startResolver(t)
	up.drop(func(int64) bool { return true })
	s := startService(t, ModeAuto, up)
	for i := range 5 {
		resp, took := ask(t, s, fmt.Sprintf("dead-%d.example", i))
		if len(resp.Answer) != 1 {
			t.Fatalf("no answer: %v", resp)
		}
		if took > 1500*time.Millisecond {
			t.Errorf("took %v", took)
		}
	}
}

func TestModeTCPNeverAsksOverUDP(t *testing.T) {
	up := startResolver(t)
	s := startService(t, ModeTCP, up)
	for i := range 30 {
		ask(t, s, fmt.Sprintf("tcp-only-%d.example", i))
	}
	if up.udp.Load() != 0 || up.tcp.Load() != 30 {
		t.Fatalf("udp %d tcp %d, want 0 and 30", up.udp.Load(), up.tcp.Load())
	}
}

// An answer too large for UDP is fetched whole over TCP, and a client that
// asked over UDP is told to come back over TCP, as Go's resolver does.
func TestLargeAnswersArriveWhole(t *testing.T) {
	up := startResolver(t, func(req *dns.Msg, overUDP bool) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if req.Question[0].Qtype != dns.TypeA {
			return resp
		}
		if overUDP {
			resp.Truncated = true
			return resp
		}
		for i := range 120 {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, byte(i+1)),
			})
		}
		return resp
	})
	s := startService(t, ModeAuto, up)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := s.Resolver().LookupNetIP(ctx, "ip4", "large.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 120 {
		t.Fatalf("%d addresses, want 120", len(addrs))
	}
}

func TestNextResolverWhenTheFirstFails(t *testing.T) {
	sound := startResolver(t)
	failing := startResolver(t, func(req *dns.Msg, _ bool) *dns.Msg {
		resp := new(dns.Msg)
		return resp.SetRcode(req, dns.RcodeServerFailure)
	})
	s := startService(t, ModeAuto, failing, sound)
	if resp, _ := ask(t, s, "second.example"); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("answer %v", resp)
	}
}

// A first resolver that answers nothing at all costs the first queries its
// timeout and none after.
func TestDeadResolverIsAskedLast(t *testing.T) {
	sound := startResolver(t)
	gone, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := gone.LocalAddr().String()
	_ = gone.Close()
	s, _, err := Start(Config{Servers: []string{dead, sound.addr}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	for i := range 3 {
		if resp, _ := ask(t, s, fmt.Sprintf("warm-%d.example", i)); len(resp.Answer) != 1 {
			t.Fatalf("answer %v", resp)
		}
	}
	if _, took := ask(t, s, "after.example"); took > 300*time.Millisecond {
		t.Errorf("a query took %v with the dead resolver known", took)
	}
}

func TestNegativeAnswersAreKept(t *testing.T) {
	up := startResolver(t, func(req *dns.Msg, _ bool) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeNameError)
		resp.Ns = append(resp.Ns, &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns: "ns.example.", Mbox: "h.example.", Minttl: 60})
		return resp
	})
	s := startService(t, ModeAuto, up)
	for range 3 {
		if resp, _ := ask(t, s, "missing.example"); resp.Rcode != dns.RcodeNameError {
			t.Fatalf("answer %v", resp)
		}
	}
	if n := up.udp.Load() + up.tcp.Load(); n != 1 {
		t.Fatalf("asked %d times", n)
	}
}

func TestEnableMakesGoResolveThroughTheForwarder(t *testing.T) {
	up := startResolver(t)
	if _, err := Enable(Config{Servers: []string{up.addr}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(Disable)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, "through.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "192.0.2.1" {
		t.Fatalf("resolved %v", addrs)
	}
	if up.udp.Load()+up.tcp.Load() == 0 {
		t.Fatal("the resolver was not asked")
	}
	Disable()
	if Active() != nil {
		t.Fatal("still active")
	}
}

func TestSystemUpstreams(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldConf, oldResolved := resolvConfPath, resolvedConfPath
	t.Cleanup(func() { resolvConfPath, resolvedConfPath = oldConf, oldResolved })
	resolvedConfPath = write("resolved.conf", "nameserver 203.0.113.7\nnameserver 2001:db8::7\n")
	for _, c := range []struct {
		name, conf string
		want       []string
		local      bool
	}{
		{"plain", "search lan\nnameserver 198.51.100.1\nnameserver 198.51.100.1\nnameserver 198.51.100.2\n", []string{"198.51.100.1:53", "198.51.100.2:53"}, false},
		{"systemd-resolved's stub", "nameserver 127.0.0.53\noptions edns0 trust-ad\n", []string{"203.0.113.7:53", "[2001:db8::7]:53"}, false},
		{"a resolver on this machine", "nameserver 127.0.0.1\n", nil, true},
		{"Docker's", "nameserver 127.0.0.11\n", nil, true},
		{"none", "# empty\n", fallbackServers, false},
	} {
		resolvConfPath = write("resolv.conf", c.conf)
		got, local := systemUpstreams()
		if local != c.local || fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: %v local=%v, want %v local=%v", c.name, got, local, c.want, c.local)
		}
	}
	// With one on this machine there is nothing to start.
	resolvConfPath = write("resolv.conf", "nameserver 127.0.0.1\n")
	if s, reason, err := Start(Config{}); s != nil || err != nil || reason == "" {
		t.Fatalf("started %v, %q, %v", s, reason, err)
	}
	if _, _, err := Start(Config{Mode: "fast"}); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	if _, _, err := Start(Config{Servers: []string{"dns.example"}}); err == nil {
		t.Fatal("a server by name was accepted")
	}
}

// One lost query is not a lossy path; three in the window are.
func TestOneLostQueryDoesNotMoveToTCP(t *testing.T) {
	moves := 0
	u := &upstream{addr: "192.0.2.1:53", changed: func(string, bool, int, int) { moves++ }}
	u.record(true, 0)
	for range lossWindow - 1 {
		u.record(false, 10*time.Millisecond)
	}
	if u.overTCP() || moves != 0 {
		t.Fatal("moved to TCP for one lost query in fifty")
	}
	// The lost one has left the window by now.
	for range lossLeast {
		u.record(true, 0)
	}
	if !u.overTCP() || moves != 1 {
		t.Fatalf("on UDP with %d of the last %d lost", lossLeast, lossWindow)
	}
}
