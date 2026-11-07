package hy2

import (
	"net"
	"net/netip"

	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/apernet/hysteria/extras/v2/outbounds"
	"go.uber.org/zap"
)

// destinationGuard holds a node's users to the destinations the other cores
// allow theirs.
//
// Unless Hysteria2ConfigPath set an ACL, a node's outbound was a bare direct
// dial. A user could reach anything the node can reach: 127.0.0.1 (the node's
// own services, such as the TrustTunnel endpoint's metrics port, which serves
// and resets every user's traffic counters), the hosting provider's private
// network and its metadata address. The panel's audit rules were not read
// at all, so a domain, address, port or UDP the panel blocks went through
// as well. The sing, Mihomo and Xray cores refuse all of these.
//
// The guard sits in front of the node's outbound. For a name, it resolves it
// once and leaves the answer on the request, so the outbound dials what was
// checked rather than looking the name up again. It checks each TCP
// connection, the first packet of each UDP session, and each later UDP
// destination: hysteria asks CheckUDP once per address, and every datagram's
// resolved address is checked again before it is sent.
type destinationGuard struct {
	tag          string
	allowPrivate bool
	next         outbounds.PluggableOutbound
	logger       *zap.Logger
}

type refusedError struct{ reason string }

func (e refusedError) Error() string { return "destination refused: " + e.reason }

func newDestinationGuard(tag string, allowPrivate bool, next outbounds.PluggableOutbound, logger *zap.Logger) outbounds.PluggableOutbound {
	return &destinationGuard{tag: tag, allowPrivate: allowPrivate, next: next, logger: logger}
}

// privateAddress is what the Mihomo core refuses: loopback, private,
// link-local and every address that is not global unicast.
func privateAddress(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || !a.IsGlobalUnicast()
}

// resolve fills in the request's addresses as hysteria's own resolvers do:
// the first IPv4 and the first IPv6 answer.
func resolve(addr *outbounds.AddrEx) {
	if ip := net.ParseIP(addr.Host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr.ResolveInfo = &outbounds.ResolveInfo{IPv4: ip4}
		} else {
			addr.ResolveInfo = &outbounds.ResolveInfo{IPv6: ip}
		}
		return
	}
	ips, err := net.LookupIP(addr.Host)
	if err != nil {
		addr.ResolveInfo = &outbounds.ResolveInfo{Err: err}
		return
	}
	info := &outbounds.ResolveInfo{}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if info.IPv4 == nil {
				info.IPv4 = ip4
			}
		} else if info.IPv6 == nil {
			info.IPv6 = ip
		}
	}
	addr.ResolveInfo = info
}

// rules is the node's limiter, which holds the panel's audit rules; nil
// while the node is being torn down.
func (g *destinationGuard) rules() *limiter.Limiter {
	l, err := limiter.GetLimiter(g.tag)
	if err != nil {
		return nil
	}
	return l
}

// permitAddresses drops the request's resolved addresses that the guard
// refuses, and refuses the request if none is left. A failed lookup is left
// to the outbound, which reports it.
func (g *destinationGuard) permitAddresses(addr *outbounds.AddrEx, l *limiter.Limiter) error {
	if addr.ResolveInfo == nil {
		resolve(addr)
	}
	r := addr.ResolveInfo
	if r.IPv4 == nil && r.IPv6 == nil {
		return nil
	}
	reason := ""
	permitted := func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		if !g.allowPrivate && privateAddress(ip) {
			reason = "a private address (AllowPrivateDestinations is off)"
			return false
		}
		if l != nil {
			if reject, kind := l.CheckDestinationRule(ip.String(), addr.Port); reject {
				reason = "a panel " + kind + " rule"
				return false
			}
		}
		return true
	}
	ip4, ip6 := r.IPv4, r.IPv6
	keep4, keep6 := permitted(ip4), permitted(ip6)
	if !keep4 && !keep6 {
		return refusedError{reason}
	}
	// A copy: the resolver's answer is not the guard's to change.
	next := &outbounds.ResolveInfo{Err: r.Err}
	if keep4 {
		next.IPv4 = ip4
	}
	if keep6 {
		next.IPv6 = ip6
	}
	addr.ResolveInfo = next
	return nil
}

// check applies the panel's rules for the requested name or address, then
// the address checks.
func (g *destinationGuard) check(addr *outbounds.AddrEx, udp bool) error {
	l := g.rules()
	if l != nil {
		if udp && l.CheckProtocolRule("udp") {
			return refusedError{"a panel rule blocks UDP"}
		}
		if reject, kind := l.CheckDestinationRule(addr.Host, addr.Port); reject {
			return refusedError{"a panel " + kind + " rule"}
		}
	}
	return g.permitAddresses(addr, l)
}

func (g *destinationGuard) refused(network string, addr *outbounds.AddrEx, err error) {
	if g.logger != nil {
		g.logger.Info("refused a destination", zap.String("tag", g.tag), zap.String("network", network), zap.String("reqAddr", addr.String()), zap.Error(err))
	}
}

func (g *destinationGuard) TCP(addr *outbounds.AddrEx) (net.Conn, error) {
	if err := g.check(addr, false); err != nil {
		g.refused("tcp", addr, err)
		return nil, err
	}
	return g.next.TCP(addr)
}

func (g *destinationGuard) UDP(addr *outbounds.AddrEx) (outbounds.UDPConn, error) {
	if err := g.check(addr, true); err != nil {
		g.refused("udp", addr, err)
		return nil, err
	}
	conn, err := g.next.UDP(addr)
	if err != nil {
		return nil, err
	}
	return &guardedUDPConn{UDPConn: conn, guard: g}, nil
}

func (g *destinationGuard) CheckUDP(addr *outbounds.AddrEx) error {
	if err := g.check(addr, true); err != nil {
		g.refused("udp", addr, err)
		return err
	}
	return g.next.CheckUDP(addr)
}

// guardedUDPConn checks each datagram's resolved address: hysteria asks
// CheckUDP once per address and caches the answer, while the outbound
// resolves a name again for every datagram, so a name could pass the check
// and then be sent to whatever it resolves to next.
type guardedUDPConn struct {
	outbounds.UDPConn
	guard *destinationGuard
}

func (c *guardedUDPConn) WriteTo(b []byte, addr *outbounds.AddrEx) (int, error) {
	if err := c.guard.permitAddresses(addr, nil); err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, addr)
}
