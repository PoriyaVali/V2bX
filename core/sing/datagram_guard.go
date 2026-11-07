package sing

import (
	"fmt"
	"time"

	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// maxCheckedDestinations bounds what a UDP session remembers of the
// destinations it has checked; past it, the record starts over.
const maxCheckedDestinations = 64

// datagramGuard applies the private-address block and the panel's rules to
// each datagram of a UDP session, not only to the session's first
// destination.
//
// A full-cone session names each datagram's destination, and sing-box sends
// it there: XUDP (which VLESS and VMess clients use for UDP), Trojan,
// Shadowsocks, Hysteria, Hysteria2, TUIC and AnyTLS's UDP over TCP. The route
// rules, the private-address ones among them, and the checks in
// RoutedPacketConnection judged the destination the session opened with. A
// user reached a blocked port or address, or the node's own services on
// 127.0.0.1 and its private network, by sending one datagram somewhere
// allowed first. A refused datagram is dropped, and the session goes on.
type datagramGuard struct {
	limiter       *limiter.Limiter
	allowPrivate  bool
	inbound, user string
	first         M.Socksaddr
	checked       map[M.Socksaddr]bool
}

func newDatagramGuard(l *limiter.Limiter, allowPrivate bool, inbound, user string, first M.Socksaddr) *datagramGuard {
	return &datagramGuard{limiter: l, allowPrivate: allowPrivate, inbound: inbound, user: user,
		first: first, checked: make(map[M.Socksaddr]bool)}
}

// permits is whether a datagram to destination may go on. Only the reading
// goroutine of the session calls it.
func (g *datagramGuard) permits(destination M.Socksaddr) bool {
	if destination == g.first {
		return true
	}
	if permitted, ok := g.checked[destination]; ok {
		return permitted
	}
	reason := g.refusal(destination)
	if reason != "" && logEvery("udp|"+g.inbound+"|"+g.user+"|"+destination.String(), time.Minute) {
		log.Error(fmt.Sprintf("User %s access udp %s reject by %s", g.user, destination, reason))
	}
	if len(g.checked) >= maxCheckedDestinations {
		clear(g.checked)
	}
	g.checked[destination] = reason == ""
	return reason == ""
}

// refusal says why a datagram to destination is refused, or "" if it is not.
func (g *datagramGuard) refusal(destination M.Socksaddr) string {
	if destination.IsFqdn() {
		if reject, kind := g.limiter.CheckDestinationRule(destination.Fqdn, destination.Port); reject {
			return kind + " rule"
		}
		// sing-box resolves the name a session opened with, and the route
		// rules checked its addresses; where another name leads is not known
		// here. (The direct outbound cannot send to one either.)
		if !g.allowPrivate {
			return "the private-address rule (a name the session did not open with)"
		}
		return ""
	}
	addr := destination.Addr.Unmap()
	if !g.allowPrivate && !N.IsPublicAddr(addr) {
		return "the private-address rule"
	}
	if reject, kind := g.limiter.CheckDestinationRule(addr.String(), destination.Port); reject {
		return kind + " rule"
	}
	return ""
}
