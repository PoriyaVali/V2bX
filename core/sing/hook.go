package sing

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/common/rate"

	"github.com/PoriyaVali/V2bX/limiter"

	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*HookServer)(nil)

type HookServer struct {
	counter sync.Map //map[string]*counter.TrafficCounter
	conns   sync.Map //map[string]*userConns, keyed by format.UserTag
}

// userConns holds the connections a single user currently has open on one
// inbound, so they can be torn down the moment the panel stops listing them.
//
// Removing a user from the inbound only stops the NEXT handshake; anything
// already established keeps running until it ends on its own. On a metered
// tier that is the difference between "your credit ran out" and "your credit
// ran out but the download you started finishes anyway".
type userConns struct {
	mu     sync.Mutex
	m      map[io.Closer]struct{}
	closed bool // set once the user is gone, so a racing registration is refused
}

// trackedConn removes itself from its user's set as soon as it closes, however
// it closes. Without that the set only ever grows and the node leaks memory for
// the lifetime of the process - far worse than the billing gap being fixed.
type trackedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		if c.release != nil {
			c.release()
		}
	})
	return c.Conn.Close()
}

// The three methods below keep this wrapper out of the data path.
//
// What it wraps is a *counter.ConnCounter, which is not a plain net.Conn: it
// carries ReadBuffer/WriteBuffer plus sing's unwrap protocol (Upstream,
// UnwrapReader, UnwrapWriter) that lets a copy run straight against the raw
// connection while the byte counts are applied through CountFuncs. Embedding
// an INTERFACE only promotes that interface's own methods, so wrapping in
// net.Conn hid every one of them - sing could no longer see a counter, chose a
// copy path that never went through it, and traffic stopped being counted
// while data kept flowing perfectly. Nothing failed; the numbers simply went
// quiet, which cost a release to notice.
//
// Declaring the upstream replaceable hands reads and writes back to the
// counter untouched. Close still belongs to this type, which is all the
// tracking needs.
func (c *trackedConn) Upstream() any { return c.Conn }

func (c *trackedConn) ReaderReplaceable() bool { return true }

func (c *trackedConn) WriterReplaceable() bool { return true }

// The three methods below keep this wrapper out of the data path.
//
// What it wraps is a *counter.ConnCounter, which is not a plain net.Conn: it
// carries ReadBuffer/WriteBuffer plus sing's unwrap protocol (Upstream,
// UnwrapReader, UnwrapWriter) that lets a copy run straight against the raw
// connection while the byte counts are applied through CountFuncs. Embedding
// an INTERFACE only promotes that interface's own methods, so wrapping in
// net.Conn hid every one of them - sing could no longer see a counter, chose a
// copy path that never went through it, and traffic stopped being counted
// while data kept flowing perfectly. Nothing failed; the numbers simply went
// quiet, which cost a release to notice.
//
// Declaring the upstream replaceable hands reads and writes back to the
// counter untouched. Close still belongs to this type, which is all the
// tracking needs.

type trackedPacketConn struct {
	N.PacketConn
	release func()
	once    sync.Once
}

func (c *trackedPacketConn) Close() error {
	c.once.Do(func() {
		if c.release != nil {
			c.release()
		}
	})
	return c.PacketConn.Close()
}

// Same reasoning as trackedConn: PacketConnCounter carries the packet unwrap
// protocol, and hiding it would silently stop UDP being counted.
func (c *trackedPacketConn) Upstream() any { return c.PacketConn }

func (c *trackedPacketConn) ReaderReplaceable() bool { return true }

func (c *trackedPacketConn) WriterReplaceable() bool { return true }

// Same reasoning as trackedConn: PacketConnCounter carries the packet unwrap
// protocol, and hiding it would silently stop UDP being counted.

func (h *HookServer) register(key string, c io.Closer) (func(), bool) {
	v, _ := h.conns.LoadOrStore(key, &userConns{m: make(map[io.Closer]struct{})})
	uc := v.(*userConns)
	uc.mu.Lock()
	if uc.closed {
		uc.mu.Unlock()
		return nil, false
	}
	uc.m[c] = struct{}{}
	uc.mu.Unlock()
	return func() {
		uc.mu.Lock()
		delete(uc.m, c)
		uc.mu.Unlock()
	}, true
}

// CloseUserConns drops every connection these users still have open on the
// inbound. Returns how many were closed.
func (h *HookServer) CloseUserConns(inbound string, uuids []string) int {
	closed := 0
	for _, uuid := range uuids {
		v, ok := h.conns.LoadAndDelete(format.UserTag(inbound, uuid))
		if !ok {
			continue
		}
		uc := v.(*userConns)
		// Collect under the lock but close OUTSIDE it: Close() runs the
		// release func, which takes this same mutex, so closing while holding
		// it would deadlock the node.
		uc.mu.Lock()
		uc.closed = true
		list := make([]io.Closer, 0, len(uc.m))
		for c := range uc.m {
			list = append(list, c)
		}
		uc.m = nil
		uc.mu.Unlock()
		for _, c := range list {
			_ = c.Close()
			closed++
		}
	}
	return closed
}

func (h *HookServer) ModeList() []string {
	return nil
}

func (h *HookServer) RoutedConnection(_ context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		return conn
	}
	taguuid := format.UserTag(m.Inbound, m.User)
	ip := m.Source.Addr.String()
	// A source that is one of this node's own addresses is not a user device,
	// so it must not be registered as an online IP nor checked against the
	// device limit — speed limits and access rules below still apply.
	countDevice := !isNodeOwnedIP(m.Source.Addr)
	if !countDevice {
		warnNodeOwnedSource(m.Inbound, ip)
	}
	if b, r := l.CheckLimit(taguuid, ip, true, countDevice); r {
		conn.Close()
		log.Error("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return conn
	} else if b != nil {
		conn = rate.NewConnRateLimiter(conn, b)
	}
	if l != nil {
		destStr := m.Destination.AddrString()
		protocol := m.Protocol
		if l.CheckDomainRule(destStr) {
			log.Error(fmt.Sprintf(
				"User %s access domain %s reject by rule",
				m.User,
				destStr))
			conn.Close()
			return conn
		}
		if len(protocol) != 0 {
			if l.CheckProtocolRule(protocol) {
				log.Error(fmt.Sprintf(
					"User %s access protocol %s reject by rule",
					m.User,
					protocol))
				conn.Close()
				return conn
			}
		}
	}
	var t *counter.TrafficCounter
	if c, ok := h.counter.Load(m.Inbound); !ok {
		t = counter.NewTrafficCounter()
		h.counter.Store(m.Inbound, t)
	} else {
		t = c.(*counter.TrafficCounter)
	}
	conn = counter.NewConnCounter(conn, t.GetCounter(m.User))
	tc := &trackedConn{Conn: conn}
	release, ok := h.register(taguuid, tc)
	if !ok {
		// the user was removed while this was being set up
		conn.Close()
		return conn
	}
	tc.release = release
	return tc
}

func (h *HookServer) RoutedPacketConnection(_ context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		return conn
	}
	ip := m.Source.Addr.String()
	taguuid := format.UserTag(m.Inbound, m.User)
	if b, r := l.CheckLimit(taguuid, ip, false, false); r {
		conn.Close()
		log.Error("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return conn
	} else if b != nil {
		//conn = rate.NewPacketConnCounter(conn, b)
	}
	if l != nil {
		destStr := m.Destination.AddrString()
		protocol := m.Destination.Network()
		if l.CheckDomainRule(destStr) {
			log.Error(fmt.Sprintf(
				"User %s access domain %s reject by rule",
				m.User,
				destStr))
			conn.Close()
			return conn
		}
		if len(protocol) != 0 {
			if l.CheckProtocolRule(protocol) {
				log.Error(fmt.Sprintf(
					"User %s access protocol %s reject by rule",
					m.User,
					protocol))
				conn.Close()
				return conn
			}
		}
	}
	var t *counter.TrafficCounter
	if c, ok := h.counter.Load(m.Inbound); !ok {
		t = counter.NewTrafficCounter()
		h.counter.Store(m.Inbound, t)
	} else {
		t = c.(*counter.TrafficCounter)
	}
	conn = counter.NewPacketConnCounter(conn, t.GetCounter(m.User))
	pc := &trackedPacketConn{PacketConn: conn}
	release, ok := h.register(taguuid, pc)
	if !ok {
		conn.Close()
		return conn
	}
	pc.release = release
	return pc
}
