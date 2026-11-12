package smartdns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// lossWindow is how many of the latest UDP queries the loss is taken over.
	lossWindow = 50
	// lossSamples is how many it takes before the loss means anything.
	lossSamples = 20
	// lossToTCP, in percent of the window: at this loss queries go over TCP.
	// A resolver on a sound path loses well under one in a hundred.
	lossToTCP = 5
	// lossLeast is how many queries must be lost as well: one lost packet is
	// not a lossy path.
	lossLeast = 3
	// probeEvery is how often, in queries, a resolver that is asked over TCP
	// is also asked over UDP, to see whether its UDP path has recovered: a
	// full window of probes without one lost puts it back on UDP.
	probeEvery = 10

	udpTimeout  = 2 * time.Second
	tcpTimeout  = 3 * time.Second
	minPatience = 150 * time.Millisecond
	maxPatience = time.Second
	// tcpIdle is how long a TCP connection is kept for the next query.
	// Public resolvers close idle ones after about ten seconds.
	tcpIdle    = 8 * time.Second
	tcpIdleMax = 8
)

type idleConn struct {
	conn net.Conn
	used time.Time
}

// upstream is one resolver, asked over UDP while its answers arrive and over
// TCP while they do not.
type upstream struct {
	addr     string
	forceTCP bool
	// changed is told when the resolver moves between UDP and TCP.
	changed func(addr string, tcp bool, lost, of int)
	// failures counts the queries in a row it gave no answer to at all.
	failures atomic.Int32

	mu       sync.Mutex
	window   [lossWindow]bool // true: the query got no answer
	filled   int
	next     int
	lost     int
	tcpFirst bool
	sinceUDP int
	srtt     time.Duration
	idle     []idleConn
	closed   bool
}

// plan says how the next query goes: over TCP first or not, and whether it
// also probes UDP.
func (u *upstream) plan() (tcpFirst, probe bool) {
	if u.forceTCP {
		return true, false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.tcpFirst {
		return false, false
	}
	u.sinceUDP++
	if u.sinceUDP >= probeEvery {
		u.sinceUDP = 0
		return true, true
	}
	return true, false
}

// patience is how long a UDP answer is waited for before TCP is asked too.
func (u *upstream) patience() time.Duration {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.srtt == 0 {
		return 400 * time.Millisecond
	}
	p := 4 * u.srtt
	if p < minPatience {
		p = minPatience
	}
	if p > maxPatience {
		p = maxPatience
	}
	return p
}

// record notes how a UDP query ended.
func (u *upstream) record(lost bool, rtt time.Duration) {
	u.mu.Lock()
	if u.filled == lossWindow {
		if u.window[u.next] {
			u.lost--
		}
	} else {
		u.filled++
	}
	u.window[u.next] = lost
	u.next = (u.next + 1) % lossWindow
	if lost {
		u.lost++
	} else if u.srtt == 0 {
		u.srtt = rtt
	} else {
		u.srtt += (rtt - u.srtt) / 8
	}
	var notify func()
	switch {
	case !u.tcpFirst && u.filled >= lossSamples && u.lost >= lossLeast && u.lost*100 >= lossToTCP*u.filled:
		lostN, of := u.lost, u.filled
		u.tcpFirst = true
		u.resetWindow()
		notify = func() { u.changed(u.addr, true, lostN, of) }
	case u.tcpFirst && u.filled == lossWindow && u.lost == 0:
		u.tcpFirst = false
		u.resetWindow()
		notify = func() { u.changed(u.addr, false, 0, lossWindow) }
	}
	u.mu.Unlock()
	if notify != nil && u.changed != nil {
		notify()
	}
}

func (u *upstream) resetWindow() {
	u.window = [lossWindow]bool{}
	u.filled, u.next, u.lost, u.sinceUDP = 0, 0, 0, 0
}

func (u *upstream) overTCP() bool {
	if u.forceTCP {
		return true
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.tcpFirst
}

type answer struct {
	msg []byte
	err error
	udp bool
}

// exchange asks the resolver query, a packed DNS message, and returns its
// packed answer.
func (u *upstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	tcpFirst, probe := u.plan()
	if tcpFirst {
		if probe {
			go func() { _, _ = u.udp(query) }()
		}
		msg, err := u.tcp(ctx, query)
		if err == nil || u.forceTCP {
			return msg, err
		}
		// TCP fails too: UDP is what is left.
		return u.udp(query)
	}
	// UDP first. TCP joins once the answer is late, and the first to answer
	// wins; the UDP query runs to its own end either way, so that a late
	// answer is not counted as a lost one.
	answers := make(chan answer, 2)
	go func() {
		msg, err := u.udp(query)
		answers <- answer{msg, err, true}
	}()
	startTCP := func() {
		go func() {
			msg, err := u.tcp(ctx, query)
			answers <- answer{msg, err, false}
		}()
	}
	late := time.NewTimer(u.patience())
	defer late.Stop()
	pending, viaTCP := 1, false
	var lastErr error
	for pending > 0 {
		select {
		case a := <-answers:
			pending--
			if a.err == nil && !(a.udp && truncated(a.msg)) {
				return a.msg, nil
			}
			if a.err != nil {
				lastErr = a.err
			}
			// A truncated or failed UDP answer: TCP has the whole one.
			if a.udp && !viaTCP {
				viaTCP = true
				pending++
				startTCP()
			}
		case <-late.C:
			if !viaTCP {
				viaTCP = true
				pending++
				startTCP()
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no answer")
	}
	return nil, lastErr
}

func truncated(msg []byte) bool { return len(msg) >= 12 && msg[2]&0x02 != 0 }

// answers reports whether msg is a response to query.
func answers(query, msg []byte) bool {
	return len(msg) >= 12 && msg[0] == query[0] && msg[1] == query[1] && msg[2]&0x80 != 0
}

// udp asks over UDP, from a socket of its own, and records the outcome.
func (u *upstream) udp(query []byte) ([]byte, error) {
	start := time.Now()
	msg, err := u.udpOnce(query, start.Add(udpTimeout))
	u.record(err != nil, time.Since(start))
	return msg, err
}

func (u *upstream) udpOnce(query []byte, deadline time.Time) ([]byte, error) {
	conn, err := net.DialTimeout("udp", u.addr, udpTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if answers(query, buf[:n]) {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// tcp asks over TCP, on a connection kept from an earlier query when there is
// one. A kept connection the resolver has closed meanwhile is replaced once.
func (u *upstream) tcp(ctx context.Context, query []byte) ([]byte, error) {
	deadline := time.Now().Add(tcpTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for {
		conn, kept := u.take()
		if conn == nil {
			d := net.Dialer{Deadline: deadline}
			var err error
			if conn, err = d.DialContext(ctx, "tcp", u.addr); err != nil {
				return nil, err
			}
		}
		msg, err := roundTrip(conn, query, deadline)
		if err == nil {
			u.keep(conn)
			return msg, nil
		}
		_ = conn.Close()
		if !kept {
			return nil, err
		}
	}
}

func roundTrip(conn net.Conn, query []byte, deadline time.Time) ([]byte, error) {
	_ = conn.SetDeadline(deadline)
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	if !answers(query, msg) {
		return nil, errors.New("the resolver answered another query")
	}
	return msg, nil
}

func (u *upstream) take() (net.Conn, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for len(u.idle) > 0 {
		c := u.idle[len(u.idle)-1]
		u.idle = u.idle[:len(u.idle)-1]
		if time.Since(c.used) < tcpIdle {
			return c.conn, true
		}
		_ = c.conn.Close()
	}
	return nil, false
}

func (u *upstream) keep(conn net.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || len(u.idle) >= tcpIdleMax {
		_ = conn.Close()
		return
	}
	u.idle = append(u.idle, idleConn{conn, time.Now()})
}

func (u *upstream) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	for _, c := range u.idle {
		_ = c.conn.Close()
	}
	u.idle = nil
}
