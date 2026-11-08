//go:build with_utls

package vless

import (
	"net"
	"testing"

	utls "github.com/metacubex/utls"
)

// realityLike stands in for sing-box's REALITY server connection: a
// *utls.Conn behind a wrapper that names it as its upstream.
type realityLike struct{ *utls.Conn }

func (c *realityLike) Upstream() any { return c.Conn }

// 🔴 Regression: Vision takes a REALITY connection from sing-box 1.13, which
// is a metacubex/utls connection. Only crypto/tls and xtls/reality were
// known, so every VLESS REALITY Vision user was refused.
func TestVisionTakesUTLSConnections(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server := utls.Server(a, &utls.Config{})
	for name, conn := range map[string]net.Conn{"utls": server, "REALITY wrapper": &realityLike{server}} {
		vision, err := NewVisionConn(conn, conn, [16]byte{}, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if vision.netConn != a {
			t.Fatalf("%s: Vision would splice %v, not the connection under TLS", name, vision.netConn)
		}
	}
}
