// Package localip identifies connection sources that belong to the node itself
// (loopback, this machine's own interface IPs, or empty/invalid addresses)
// rather than a real user device. Such sources must not be registered as
// online IPs or counted against a user's device limit — e.g. traffic arriving
// from a local reverse proxy / tunnel front (Hedioum) shows a 127.0.0.1 source.
package localip

import (
	"net"
	"net/netip"
	"strings"
	"sync"
)

var (
	once    sync.Once
	nodeIPs map[netip.Addr]struct{}
	warned  sync.Map
)

func load() {
	nodeIPs = make(map[netip.Addr]struct{})
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			nodeIPs[addr.Unmap()] = struct{}{}
		}
	}
}

// IsNodeOwned reports whether ip is empty/unparseable, loopback, unspecified,
// or bound to one of this machine's own interfaces — i.e. NOT a user device.
// ip may be a bare address or host:port.
func IsNodeOwned(ip string) bool {
	ip = strings.TrimPrefix(strings.TrimSpace(ip), "::ffff:")
	if ip == "" {
		return true // empty source -> never count it
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		if host, _, e := net.SplitHostPort(ip); e == nil {
			addr, err = netip.ParseAddr(strings.TrimPrefix(host, "::ffff:"))
		}
	}
	if err != nil {
		return true // unparseable -> don't count
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() {
		return true
	}
	once.Do(load)
	_, ok := nodeIPs[addr]
	return ok
}

// FirstSeen returns true only the first time a given ip is passed, so callers
// can log a warning once per source address instead of once per connection.
func FirstSeen(ip string) bool {
	_, loaded := warned.LoadOrStore(ip, struct{}{})
	return !loaded
}
