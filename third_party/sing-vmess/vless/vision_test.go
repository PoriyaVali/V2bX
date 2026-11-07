package vless

import (
	"crypto/tls"
	"net"
	"testing"
)

// 🔴 Regression: a Vision connection survives Go's pointer checks, on by
// default under the race detector. The TLS connection's address was carried
// as a uintptr and turned back into pointers to its input buffers, which the
// checks refuse with a fatal error.
func TestVisionPassesPointerChecks(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server := tls.Server(a, &tls.Config{})
	vision, err := NewVisionConn(server, server, [16]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if vision.netConn != a || vision.input == nil || vision.rawInput == nil {
		t.Fatalf("Vision did not find the connection under TLS and its buffers: %+v", vision)
	}
}
