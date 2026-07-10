package sing

import (
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/log"
)

// Addresses bound to this machine, plus loopback. A connection whose source is
// one of these did not come from a user's device — it originates on the node
// itself (a local reverse proxy, a relay, or an on-box client). Counting such a
// source as an online device pushes single-device users over their limit.
var (
	nodeIPOnce sync.Once
	nodeIPs    map[netip.Addr]struct{}
	warnedIPs  sync.Map
)

func loadNodeIPs() {
	nodeIPs = make(map[netip.Addr]struct{})
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Warn("device limit: cannot enumerate local addresses: ", err)
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

// isNodeOwnedIP reports whether addr is loopback or bound to a local interface.
func isNodeOwnedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() {
		return true
	}
	nodeIPOnce.Do(loadNodeIPs)
	_, ok := nodeIPs[addr]
	return ok
}

// warnNodeOwnedSource logs once per source address, so a front proxy that hides
// the real client IP stays visible without a log line per connection.
func warnNodeOwnedSource(inbound, ip string) {
	if _, loaded := warnedIPs.LoadOrStore(ip, struct{}{}); loaded {
		return
	}
	log.Warn("[", inbound, "] source ", ip,
		" is this node's own address; not counting it as an online device")
}
