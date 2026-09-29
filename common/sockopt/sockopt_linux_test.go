//go:build linux

package sockopt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProbe(t *testing.T) {
	if Congestion("no-such-algorithm") {
		t.Fatal("an algorithm the kernel does not have was reported settable")
	}
	if Congestion("") {
		t.Fatal("an empty name was reported settable")
	}
	if !Congestion("cubic") {
		t.Skip("cubic is unavailable in this kernel/container")
	}
	if !NotSentLowat() {
		t.Fatal("TCP_NOTSENT_LOWAT (Linux 3.12+) was reported unavailable")
	}
}

// acceptedPair returns an accepted connection (and its client) from a
// listener whose socket got control.
func acceptedPair(t *testing.T, control func(fd int)) (net.Conn, net.Conn) {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		return rc.Control(func(fd uintptr) {
			if control != nil {
				control(int(fd))
			}
		})
	}}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, client
}

func sockInt(t *testing.T, c net.Conn, opt int) int {
	t.Helper()
	rc, _ := c.(*net.TCPConn).SyscallConn()
	var v int
	rc.Control(func(fd uintptr) { v, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, opt) })
	return v
}

// Which listener options reach accepted connections decides where each one
// must be set. Congestion control is inherited, so setting it on the listener
// is enough. TCP_NOTSENT_LOWAT is not: it must be set per connection.
func TestListenerOptionsAndAcceptedConnections(t *testing.T) {
	cc := "cubic"
	if Congestion("bbr") {
		cc = "bbr"
	}
	server, _ := acceptedPair(t, func(fd int) {
		unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, 16384)
		unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, cc)
	})
	rc, _ := server.(*net.TCPConn).SyscallConn()
	var got string
	rc.Control(func(fd uintptr) { got, _ = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION) })
	if got != cc {
		t.Errorf("accepted connection uses %q, want %q from the listener", got, cc)
	}
	if v := sockInt(t, server, unix.TCP_NOTSENT_LOWAT); v == 16384 {
		t.Log("this kernel passes TCP_NOTSENT_LOWAT on to accepted connections; setting it per connection is still correct")
	}
}

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// SetNotSentLowat reaches the socket through the layers a core wraps around
// it, and the value really lands on the accepted connection.
func TestSetNotSentLowat(t *testing.T) {
	server, _ := acceptedPair(t, nil)
	if !SetNotSentLowat(server, 16384) || sockInt(t, server, unix.TCP_NOTSENT_LOWAT) != 16384 {
		t.Fatal("not set on a plain accepted connection")
	}

	server2, _ := acceptedPair(t, nil)
	wrapped := tls.Server(server2, selfSignedTLS(t))
	if !SetNotSentLowat(wrapped, 32768) || sockInt(t, server2, unix.TCP_NOTSENT_LOWAT) != 32768 {
		t.Fatal("not set through a TLS layer")
	}

	server3, _ := acceptedPair(t, nil)
	if !SetNotSentLowat(&upstreamWrapper{wrapped: server3}, 8192) || sockInt(t, server3, unix.TCP_NOTSENT_LOWAT) != 8192 {
		t.Fatal("not set through an Upstream() layer")
	}

	if SetNotSentLowat(&hidden{}, 16384) {
		t.Fatal("reported success for a connection that hides its socket")
	}
	if SetNotSentLowat(server, 0) {
		t.Fatal("0 must mean leave it alone")
	}
}

type upstreamWrapper struct{ wrapped net.Conn }

func (u *upstreamWrapper) Upstream() any { return u.wrapped }

type hidden struct{ net.Conn }
