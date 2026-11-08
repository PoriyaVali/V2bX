package sing

import (
	"io"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type scriptedDatagram struct {
	payload string
	to      M.Socksaddr
}

// scriptedPacketConn is a client's side of a UDP session: it reads the
// datagrams given, then io.EOF.
type scriptedPacketConn struct {
	N.PacketConn
	datagrams []scriptedDatagram
}

func (c *scriptedPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	if len(c.datagrams) == 0 {
		return M.Socksaddr{}, io.EOF
	}
	d := c.datagrams[0]
	c.datagrams = c.datagrams[1:]
	_, _ = b.WriteString(d.payload)
	return d.to, nil
}

// Each datagram of a UDP session is checked, not only the first: the session
// opens at a public address, then names others. With the private-address
// block on, a private one, a name the session did not open with and what
// the panel's rules refuse are dropped, and the session reads on. The
// end-to-end test cannot reach this one, having no public address to open a
// session at.
func TestTrackedPacketConnChecksEveryDatagram(t *testing.T) {
	l := &limiter.Limiter{}
	if err := l.UpdateRule(&panel.Rules{Regexp: []string{`blocked\.example`}, Port: []string{"9999"}}); err != nil {
		t.Fatal(err)
	}
	first := M.ParseSocksaddr("1.1.1.1:443")
	datagrams := []scriptedDatagram{
		{"first", first},
		{"loopback", M.ParseSocksaddr("127.0.0.1:53")},
		{"private", M.ParseSocksaddr("10.0.0.1:53")},
		{"loopback6", M.ParseSocksaddr("[::1]:53")},
		{"mapped", M.ParseSocksaddr("[::ffff:192.168.1.1]:53")},
		{"linklocal", M.ParseSocksaddr("169.254.169.254:53")},
		{"public", M.ParseSocksaddr("8.8.8.8:53")},
		{"blocked port", M.ParseSocksaddr("8.8.8.8:9999")},
		{"other name", M.ParseSocksaddr("example.com:53")},
		{"blocked name", M.ParseSocksaddr("blocked.example:53")},
		{"first again", first},
	}
	for _, c := range []struct {
		allowPrivate bool
		want         []string
	}{
		{false, []string{"first", "public", "first again"}},
		{true, []string{"first", "loopback", "private", "loopback6", "mapped", "linklocal", "public", "other name", "first again"}},
	} {
		pc := &trackedPacketConn{
			PacketConn: &scriptedPacketConn{datagrams: datagrams},
			guard:      newDatagramGuard(l, c.allowPrivate, "in", "user", first),
		}
		var got []string
		for {
			b := buf.NewPacket()
			b.Resize(32, 0) // headroom a protocol writes its header into
			_, err := pc.ReadPacket(b)
			if err != nil {
				b.Release()
				break
			}
			if b.Start() != 32 {
				t.Errorf("allowPrivate %v: a dropped datagram took the headroom: start %d", c.allowPrivate, b.Start())
			}
			got = append(got, string(b.Bytes()))
			b.Release()
		}
		if len(got) != len(c.want) {
			t.Fatalf("allowPrivate %v: went on %q, want %q", c.allowPrivate, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("allowPrivate %v: went on %q, want %q", c.allowPrivate, got, c.want)
			}
		}
	}
}

// What a session remembers of the destinations it checked stays bounded.
func TestDatagramGuardForgetsPastItsBound(t *testing.T) {
	g := newDatagramGuard(&limiter.Limiter{}, true, "in", "user", M.ParseSocksaddr("1.1.1.1:443"))
	for port := uint16(1); port <= 3*maxCheckedDestinations; port++ {
		if !g.permits(M.ParseSocksaddrHostPort("8.8.8.8", port)) {
			t.Fatalf("port %d refused", port)
		}
		if len(g.checked) > maxCheckedDestinations {
			t.Fatalf("%d destinations remembered", len(g.checked))
		}
	}
}
