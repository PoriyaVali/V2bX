// Package smartdns is V2bX's own DNS forwarder. Every core resolves the
// names its users connect to through the machine's resolvers, over UDP, and
// on a path that loses UDP each lost query is a connection that waits out a
// resolver timeout. The forwarder asks the same resolvers, watches how many
// UDP queries go unanswered, and asks over TCP while that is too many; it
// keeps answers for as long as their records allow.
//
// It listens on an ephemeral loopback port, never on port 53: a DNS-tunnel
// node (the mdns core) or a local resolver keeps that one.
package smartdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// Modes of Config.Mode.
const (
	ModeAuto   = "auto"   // UDP while it is answered, TCP while it is not
	ModeTCP    = "tcp"    // always TCP
	ModeSystem = "system" // no forwarder: every core resolves as it used to
)

// Config is the DNS section of config.json.
type Config struct {
	// Mode is auto (the default), tcp or system.
	Mode string
	// Servers replaces the resolvers of /etc/resolv.conf: IP addresses, with
	// or without a port.
	Servers []string
}

const (
	queryBudget = 4 * time.Second
	maxInFlight = 4096
)

// Service is a running forwarder.
type Service struct {
	addr      netip.AddrPort
	udp       *net.UDPConn
	tcp       net.Listener
	upstreams []*upstream
	cache     *cache
	slots     chan struct{}

	flightMu sync.Mutex
	flights  map[string]*flight

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type flight struct {
	done chan struct{}
	msg  *dns.Msg
}

// Start runs a forwarder. It returns nil, with the reason, where there is
// nothing for one to do: the mode is system, or resolv.conf names a resolver
// on this machine.
func Start(cfg Config) (*Service, string, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = ModeAuto
	}
	if mode != ModeAuto && mode != ModeTCP && mode != ModeSystem {
		return nil, "", fmt.Errorf("DNS mode %q: want auto, tcp or system", cfg.Mode)
	}
	servers, err := configured(cfg.Servers)
	if err != nil {
		return nil, "", err
	}
	if mode == ModeSystem {
		return nil, "DNS mode is system", nil
	}
	if len(servers) == 0 {
		var local bool
		if servers, local = systemUpstreams(); local {
			return nil, "resolv.conf names a resolver on this machine, which is left to resolve as it does", nil
		}
	}
	s := &Service{cache: newCache(), slots: make(chan struct{}, maxInFlight), flights: map[string]*flight{}}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	for _, addr := range servers {
		s.upstreams = append(s.upstreams, &upstream{addr: addr, forceTCP: mode == ModeTCP, changed: logChange})
	}
	if err := s.listen(); err != nil {
		s.cancel()
		return nil, "", err
	}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return s, "", nil
}

func logChange(addr string, tcp bool, lost, of int) {
	if tcp {
		log.WithFields(log.Fields{"resolver": addr, "lost": lost, "of": of}).
			Warn("UDP DNS queries to this resolver go unanswered: asking it over TCP until they are answered again")
		return
	}
	log.WithField("resolver", addr).Info("UDP DNS queries to this resolver are answered again: asking it over UDP")
}

// listen takes one loopback port for both UDP and TCP.
func (s *Service) listen() error {
	var last error
	for range 16 {
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return err
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			_ = udp.Close()
			last = err
			continue
		}
		s.udp, s.tcp = udp, tcp
		s.addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
		return nil
	}
	return last
}

// Addr is where the forwarder listens, over UDP and TCP.
func (s *Service) Addr() netip.AddrPort { return s.addr }

// Servers are the resolvers the forwarder asks.
func (s *Service) Servers() []string {
	out := make([]string, len(s.upstreams))
	for i, u := range s.upstreams {
		out[i] = u.addr
	}
	return out
}

// OverTCP reports whether the first resolver is being asked over TCP: its
// UDP queries go unanswered, or the mode is tcp.
func (s *Service) OverTCP() bool { return s.upstreams[0].overTCP() }

// Close stops the forwarder.
func (s *Service) Close() {
	s.cancel()
	_ = s.udp.Close()
	_ = s.tcp.Close()
	s.wg.Wait()
	for _, u := range s.upstreams {
		u.close()
	}
}

// Resolver is a Go resolver that asks the forwarder. It still reads
// /etc/hosts and resolv.conf's search list itself.
func (s *Service) Resolver() *net.Resolver {
	addr := s.addr.String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			if strings.HasPrefix(network, "tcp") {
				return d.DialContext(ctx, "tcp4", addr)
			}
			return d.DialContext(ctx, "udp4", addr)
		},
	}
}

func (s *Service) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		select {
		case s.slots <- struct{}{}:
		default:
			continue // overloaded: the client asks again
		}
		go func() {
			defer func() { <-s.slots }()
			if out := s.handle(raw, true); out != nil {
				_, _ = s.udp.WriteToUDPAddrPort(out, from)
			}
		}()
	}
}

func (s *Service) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go s.serveConn(conn)
	}
}

func (s *Service) serveConn(conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(s.ctx, func() { _ = conn.Close() })
	defer stop()
	for {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		raw := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		out := s.handle(raw, false)
		if out == nil {
			return
		}
		framed := make([]byte, 2+len(out))
		binary.BigEndian.PutUint16(framed, uint16(len(out)))
		copy(framed[2:], out)
		if _, err := conn.Write(framed); err != nil {
			return
		}
	}
}

// handle answers one packed query; nil for what is not a query.
func (s *Service) handle(raw []byte, overUDP bool) []byte {
	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil || req.Response {
		return nil
	}
	var resp *dns.Msg
	if req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		// Nothing to key a cache on: asked as it is.
		resp = s.resolve(req)
	} else {
		key := cacheKey(req)
		if resp = s.cache.get(key, time.Now()); resp == nil {
			resp = s.shared(key, req)
		}
	}
	resp.Id = req.Id
	// The name as the client spelled it, which some check.
	if len(resp.Question) == len(req.Question) {
		resp.Question = req.Question
	}
	if overUDP {
		limit := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > limit {
			limit = int(opt.UDPSize())
		}
		// Sets TC when the answer does not fit: the client asks over TCP.
		resp.Truncate(limit)
	}
	out, err := resp.Pack()
	if err != nil {
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		out, _ = fail.Pack()
	}
	return out
}

// shared resolves a question once for everyone asking it at the same time.
func (s *Service) shared(key string, req *dns.Msg) *dns.Msg {
	s.flightMu.Lock()
	if f, ok := s.flights[key]; ok {
		s.flightMu.Unlock()
		<-f.done
		return f.msg.Copy()
	}
	f := &flight{done: make(chan struct{})}
	s.flights[key] = f
	s.flightMu.Unlock()

	f.msg = s.resolve(req)
	s.cache.put(key, f.msg, time.Now())
	s.flightMu.Lock()
	delete(s.flights, key)
	s.flightMu.Unlock()
	close(f.done)
	return f.msg.Copy()
}

// resolve asks the resolvers in turn until one gives an answer to keep.
func (s *Service) resolve(req *dns.Msg) *dns.Msg {
	ctx, cancel := context.WithTimeout(s.ctx, queryBudget)
	defer cancel()
	out := req.Copy()
	out.Id = dns.Id()
	query, err := out.Pack()
	var kept *dns.Msg
	if err == nil {
		for _, u := range s.inOrder() {
			raw, err := u.exchange(ctx, query)
			if err != nil {
				u.failures.Add(1)
				if ctx.Err() != nil {
					break
				}
				continue
			}
			u.failures.Store(0)
			msg := new(dns.Msg)
			if err := msg.Unpack(raw); err != nil || !sameQuestion(req, msg) {
				continue
			}
			kept = msg
			// A resolver that cannot or will not answer: the next may.
			if msg.Rcode != dns.RcodeServerFailure && msg.Rcode != dns.RcodeRefused {
				break
			}
		}
	}
	if kept == nil {
		kept = new(dns.Msg)
		kept.SetRcode(req, dns.RcodeServerFailure)
	}
	return kept
}

// inOrder is the resolvers as configured, those that have just failed to
// answer at all behind the others: a dead first resolver must not cost every
// query its timeout.
func (s *Service) inOrder() []*upstream {
	if len(s.upstreams) == 1 {
		return s.upstreams
	}
	var ok, failing []*upstream
	for _, u := range s.upstreams {
		if u.failures.Load() >= 2 {
			failing = append(failing, u)
		} else {
			ok = append(ok, u)
		}
	}
	return append(ok, failing...)
}

func sameQuestion(req, resp *dns.Msg) bool {
	if len(req.Question) != len(resp.Question) {
		return false
	}
	for i, q := range req.Question {
		r := resp.Question[i]
		if q.Qtype != r.Qtype || q.Qclass != r.Qclass || !strings.EqualFold(q.Name, r.Name) {
			return false
		}
	}
	return true
}

// The forwarder every core of this process uses.
var (
	active   atomic.Pointer[Service]
	enableMu sync.Mutex
)

// Go's resolver is given its dialer once, before anything resolves, and the
// dialer looks up the forwarder each time: replacing net.DefaultResolver
// while connections are being dialled would race with them. Without a
// forwarder it dials the resolver Go asked for, which is what Go's own
// resolver does; V2bX is built without cgo, so that is the resolver it has
// always had.
func init() {
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: dialResolver}
}

func dialResolver(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	if s := active.Load(); s != nil {
		address = s.addr.String()
		if strings.HasPrefix(network, "tcp") {
			network = "tcp4"
		} else {
			network = "udp4"
		}
	}
	return d.DialContext(ctx, network, address)
}

// Active is the process's forwarder, or nil when there is none.
func Active() *Service { return active.Load() }

// Enable starts the process's forwarder, which Go's resolver then asks. It
// reports why none was started, when none was.
func Enable(cfg Config) (reason string, err error) {
	enableMu.Lock()
	defer enableMu.Unlock()
	if active.Load() != nil {
		return "", errors.New("the DNS forwarder is already running")
	}
	s, reason, err := Start(cfg)
	if err != nil || s == nil {
		return reason, err
	}
	active.Store(s)
	return "", nil
}

// Disable stops the process's forwarder: Go's resolver asks the machine's
// resolvers again.
func Disable() {
	enableMu.Lock()
	defer enableMu.Unlock()
	if s := active.Swap(nil); s != nil {
		s.Close()
	}
}
