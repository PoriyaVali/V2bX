package hy2

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/apernet/hysteria/extras/v2/outbounds"
)

// recordingOutbound stands in for the direct outbound and records what the
// guard let through, with the addresses it was handed.
type recordingOutbound struct {
	tcp, udp, check []outbounds.AddrEx
	writes          []outbounds.AddrEx
}

func (r *recordingOutbound) TCP(a *outbounds.AddrEx) (net.Conn, error) {
	r.tcp = append(r.tcp, *a)
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func (r *recordingOutbound) UDP(a *outbounds.AddrEx) (outbounds.UDPConn, error) {
	r.udp = append(r.udp, *a)
	return recordingUDPConn{r}, nil
}

func (r *recordingOutbound) CheckUDP(a *outbounds.AddrEx) error {
	r.check = append(r.check, *a)
	return nil
}

type recordingUDPConn struct{ r *recordingOutbound }

func (u recordingUDPConn) ReadFrom([]byte) (int, *outbounds.AddrEx, error) { return 0, nil, io.EOF }
func (u recordingUDPConn) WriteTo(b []byte, a *outbounds.AddrEx) (int, error) {
	u.r.writes = append(u.r.writes, *a)
	return len(b), nil
}
func (u recordingUDPConn) Close() error { return nil }

func guardFor(t *testing.T, tag string, allowPrivate bool, rules *panel.Rules) (outbounds.PluggableOutbound, *recordingOutbound) {
	t.Helper()
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, nil, map[int]int{})
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	if rules != nil {
		l, err := limiter.GetLimiter(tag)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.UpdateRule(rules); err != nil {
			t.Fatal(err)
		}
	}
	next := &recordingOutbound{}
	return newDestinationGuard(tag, allowPrivate, next, nil), next
}

func addr(host string, port uint16) *outbounds.AddrEx {
	return &outbounds.AddrEx{Host: host, Port: port}
}

func refused(err error) bool {
	var r refusedError
	return errors.As(err, &r)
}

// 🔴 The node's own services, its private network and the provider's
// metadata address are out of reach, by address and by a name that resolves
// to one. A Hysteria2 node let its users dial all of them.
func TestGuard_RefusesPrivateDestinations(t *testing.T) {
	g, next := guardFor(t, "hy-private", false, nil)
	for _, host := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "0.0.0.0", "::1", "fd00::1", "fe80::1", "localhost"} {
		if _, err := g.TCP(addr(host, 80)); !refused(err) {
			t.Errorf("TCP to %s: err = %v, want refused", host, err)
		}
		if _, err := g.UDP(addr(host, 53)); !refused(err) {
			t.Errorf("UDP to %s: err = %v, want refused", host, err)
		}
		if err := g.CheckUDP(addr(host, 53)); !refused(err) {
			t.Errorf("a later UDP packet to %s: err = %v, want refused", host, err)
		}
	}
	if len(next.tcp)+len(next.udp)+len(next.check) != 0 {
		t.Fatalf("refused requests reached the outbound: %+v", next)
	}
}

// A public address goes through, already resolved, so that the outbound dials
// the address that was checked.
func TestGuard_PassesPublicDestinationsResolved(t *testing.T) {
	g, next := guardFor(t, "hy-public", false, nil)
	if _, err := g.TCP(addr("1.1.1.1", 443)); err != nil {
		t.Fatal(err)
	}
	if len(next.tcp) != 1 || next.tcp[0].ResolveInfo == nil || !next.tcp[0].ResolveInfo.IPv4.Equal(net.IPv4(1, 1, 1, 1)) {
		t.Fatalf("outbound got %+v, want 1.1.1.1 resolved", next.tcp)
	}
}

// AllowPrivateDestinations lets them through, as on the sing and Mihomo cores.
func TestGuard_AllowPrivateDestinations(t *testing.T) {
	g, next := guardFor(t, "hy-allow", true, nil)
	if _, err := g.TCP(addr("127.0.0.1", 80)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.UDP(addr("10.0.0.1", 53)); err != nil {
		t.Fatal(err)
	}
	if len(next.tcp) != 1 || len(next.udp) != 1 {
		t.Fatalf("outbound got %+v", next)
	}
}

// 🔴 The panel's audit rules apply: blocked domains, addresses, ports and
// UDP. The Hysteria2 core never read them.
func TestGuard_AppliesThePanelsRules(t *testing.T) {
	g, next := guardFor(t, "hy-rules", false, &panel.Rules{
		Regexp:   []string{`(^|\.)blocked\.test$`},
		Domain:   []string{"full:exact.test"},
		IP:       []string{"9.9.9.9/32"},
		Port:     []string{"25"},
		Protocol: []string{"udp"},
	})
	for _, a := range []*outbounds.AddrEx{addr("www.blocked.test", 443), addr("exact.test", 443), addr("9.9.9.9", 443), addr("8.8.8.8", 25)} {
		if _, err := g.TCP(a); !refused(err) {
			t.Errorf("TCP to %s: err = %v, want refused", a, err)
		}
	}
	// A name is judged by the address it resolves to as well.
	resolved := addr("dns.example", 443)
	resolved.ResolveInfo = &outbounds.ResolveInfo{IPv4: net.IPv4(9, 9, 9, 9)}
	if _, err := g.TCP(resolved); !refused(err) {
		t.Errorf("TCP to a name resolving to a blocked address: err = %v, want refused", err)
	}
	if _, err := g.UDP(addr("8.8.8.8", 53)); !refused(err) {
		t.Errorf("UDP with a udp rule: err = %v, want refused", err)
	}
	if err := g.CheckUDP(addr("8.8.4.4", 53)); !refused(err) {
		t.Errorf("a later UDP packet with a udp rule: err = %v, want refused", err)
	}
	if _, err := g.TCP(addr("8.8.8.8", 443)); err != nil {
		t.Fatalf("an allowed destination: %v", err)
	}
	if len(next.tcp) != 1 || len(next.udp)+len(next.check) != 0 {
		t.Fatalf("outbound got %+v, want only the allowed TCP connection", next)
	}
}

// A name with one private and one public address is dialled on the public one
// only.
func TestGuard_DropsTheRefusedAddressFamily(t *testing.T) {
	g, next := guardFor(t, "hy-dual", false, nil)
	a := addr("dual.example", 443)
	public6 := net.ParseIP("2606:4700:4700::1111")
	a.ResolveInfo = &outbounds.ResolveInfo{IPv4: net.IPv4(10, 0, 0, 1), IPv6: public6}
	if _, err := g.TCP(a); err != nil {
		t.Fatal(err)
	}
	got := next.tcp[0].ResolveInfo
	if got.IPv4 != nil || !got.IPv6.Equal(public6) {
		t.Fatalf("outbound got %+v, want only the public IPv6 address", got)
	}
}

// Each datagram is checked: a UDP session that began at a public address
// cannot go on to send to a private one.
func TestGuard_ChecksEveryDatagram(t *testing.T) {
	g, next := guardFor(t, "hy-datagram", false, nil)
	conn, err := g.UDP(addr("8.8.8.8", 53))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("x"), addr("8.8.8.8", 53)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("x"), addr("127.0.0.1", 53)); !refused(err) {
		t.Fatalf("a datagram to loopback: err = %v, want refused", err)
	}
	if len(next.writes) != 1 || next.writes[0].ResolveInfo == nil || !next.writes[0].ResolveInfo.IPv4.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("outbound wrote %+v, want one datagram to 8.8.8.8, resolved", next.writes)
	}
}

// The panel's address and port rules apply to each datagram too, not only
// the private-address block: hysteria checks a name once per session, then
// resolves it again for every datagram, so a name that answered with an
// allowed address and later with one the panel blocks reached the blocked
// one. The verdict per address is remembered for the session, and a refused
// datagram leaves the session open.
func TestGuard_AppliesThePanelsRulesToEveryDatagram(t *testing.T) {
	g, next := guardFor(t, "hy-datagram-rules", false, &panel.Rules{IP: []string{"9.9.9.0/24"}, Port: []string{"9999"}})
	conn, err := g.UDP(addr("8.8.8.8", 53))
	if err != nil {
		t.Fatal(err)
	}
	resolved := func(host string, ip net.IP, port uint16) *outbounds.AddrEx {
		return &outbounds.AddrEx{Host: host, Port: port, ResolveInfo: &outbounds.ResolveInfo{IPv4: ip.To4()}}
	}
	for i := 0; i < 2; i++ { // the second time from what the session remembers
		if _, err := conn.WriteTo([]byte("x"), resolved("rebind.example", net.IPv4(9, 9, 9, 9), 53)); !refused(err) {
			t.Fatalf("a datagram to a name now resolving to a blocked address: err = %v, want refused", err)
		}
		if _, err := conn.WriteTo([]byte("x"), addr("9.9.9.10", 53)); !refused(err) {
			t.Fatalf("a datagram to a blocked address: err = %v, want refused", err)
		}
		if _, err := conn.WriteTo([]byte("x"), addr("8.8.4.4", 9999)); !refused(err) {
			t.Fatalf("a datagram to a blocked port: err = %v, want refused", err)
		}
		if _, err := conn.WriteTo([]byte("x"), resolved("rebind.example", net.IPv4(1, 1, 1, 1), 53)); err != nil {
			t.Fatalf("a datagram to an allowed address: %v", err)
		}
	}
	if len(next.writes) != 2 {
		t.Fatalf("outbound wrote %d datagrams, want the 2 to the allowed address", len(next.writes))
	}
}
