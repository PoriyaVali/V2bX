package smartdns

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

// Paths, replaced in tests.
var (
	resolvConfPath = "/etc/resolv.conf"
	// What systemd-resolved itself forwards to, when resolv.conf names its
	// stub on 127.0.0.53.
	resolvedConfPath = "/run/systemd/resolve/resolv.conf"
)

// fallbackServers are used on a machine whose resolv.conf names no server.
var fallbackServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// nameservers reads the nameserver lines of a resolv.conf.
func nameservers(path string) []netip.Addr {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if addr, err := netip.ParseAddr(fields[1]); err == nil {
			out = append(out, addr)
		}
	}
	return out
}

func isResolvedStub(a netip.Addr) bool {
	return a == netip.MustParseAddr("127.0.0.53") || a == netip.MustParseAddr("127.0.0.54")
}

// systemUpstreams are the resolvers this machine's queries end up at over the
// network. local reports that resolv.conf names a resolver on this machine
// other than systemd-resolved's stub (Unbound, dnsmasq, Docker's): what that
// one forwards to, and how, is its own business.
func systemUpstreams() (servers []string, local bool) {
	listed := nameservers(resolvConfPath)
	stub := false
	for _, a := range listed {
		switch {
		case isResolvedStub(a):
			stub = true
		case a.IsLoopback():
			local = true
		default:
			servers = append(servers, net.JoinHostPort(a.String(), "53"))
		}
	}
	if local {
		return nil, true
	}
	if stub {
		for _, a := range nameservers(resolvedConfPath) {
			if !a.IsLoopback() {
				servers = append(servers, net.JoinHostPort(a.String(), "53"))
			}
		}
	}
	if len(servers) == 0 {
		servers = append(servers, fallbackServers...)
	}
	return dedupe(servers), false
}

// configured turns the operator's list into host:port addresses.
func configured(list []string) ([]string, error) {
	var out []string
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap.String())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, &net.AddrError{Err: "a DNS server is an IP address, with or without a port", Addr: s}
		}
		out = append(out, net.JoinHostPort(a.String(), "53"))
	}
	return dedupe(out), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
