//go:build soak

package sing

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// slowSocks is a SOCKS5 server that takes delay to reach a destination - a
// stand-in for everything between a node and a slow site: a slow DNS answer,
// a far or overloaded server, a lossy route. It returns its port.
func slowSocks(t *testing.T, delay time.Duration) int {
	t.Helper()
	addr := listen(t, func(c net.Conn) {
		defer c.Close()
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(c, greeting); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, greeting[1])); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		head := make([]byte, 4)
		if _, err := io.ReadFull(c, head); err != nil {
			return
		}
		var host string
		switch head[3] {
		case 1:
			ip := make([]byte, 4)
			if _, err := io.ReadFull(c, ip); err != nil {
				return
			}
			host = net.IP(ip).String()
		case 3:
			l := make([]byte, 1)
			if _, err := io.ReadFull(c, l); err != nil {
				return
			}
			name := make([]byte, l[0])
			if _, err := io.ReadFull(c, name); err != nil {
				return
			}
			host = string(name)
		default:
			return
		}
		pb := make([]byte, 2)
		if _, err := io.ReadFull(c, pb); err != nil {
			return
		}
		time.Sleep(delay)
		target, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(pb))))
		if err != nil {
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer target.Close()
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		go func() { _, _ = io.Copy(target, c) }()
		_, _ = io.Copy(c, target)
	})
	_, port, _ := net.SplitHostPort(addr)
	var p int
	fmt.Sscan(port, &p)
	return p
}

// 🔴 A destination the node needs more than three seconds to reach must not
// cost the user the connection.
//
// AnyTLS clients reuse a pooled session for a new connection and close that
// session unless the node acknowledges the new stream (SYNACK) within three
// seconds. The node sent that acknowledgement only once it had sniffed,
// resolved and dialled the destination, so on a slow path - and on a lossy
// mobile link, where the round trip alone eats much of the three seconds - the
// client killed a perfectly healthy session, the connection failed, and the
// retry took the next pooled session into the same fate.
func TestAnytlsReusedSessionSurvivesSlowDestination(t *testing.T) {
	echo := listen(t, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) })
	slow := slowSocks(t, 4*time.Second)
	r := startSoakRigWithOutbounds(t, fmt.Sprintf(
		`{"outbounds":[{"type":"socks","tag":"slow","server":"127.0.0.1","server_port":%d,"version":"5"}]}`, slow))

	roundTrip := func(label string) {
		t.Helper()
		c, err := socksConnect(r.socksPort, echo)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatalf("%s: write: %v", label, err)
		}
		start := time.Now()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%s: connection lost after %v waiting for a slow destination: %q, %v", label, time.Since(start), buf, err)
		}
	}

	// The first stream opens the session; clients do not watch a fresh one.
	roundTrip("first stream")
	deadline := time.Now().Add(3 * time.Second)
	for r.trackedOpen() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("first AnyTLS stream did not close")
		}
		time.Sleep(time.Millisecond)
	}
	// The second reuses it, and the client starts its three-second watch.
	roundTrip("stream on a reused session")
	if sessions := anytlsSessionsHeld(t, r); sessions != 1 {
		t.Fatalf("expected the pooled session to be reused, got %d sessions", sessions)
	}
}

// With the stream acknowledged before the dial, a destination that refuses
// must still end that one connection promptly - by FIN instead of an error in
// the SYNACK - and leave the session healthy for the next one.
func TestAnytlsRefusedDestinationKeepsSessionUsable(t *testing.T) {
	r := startSoakRig(t)
	echo := listen(t, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) })
	closed := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		return addr
	}()
	ping := func(target string) error {
		c, err := socksConnect(r.socksPort, target)
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(c, buf)
		return err
	}
	waitIdle := func() {
		deadline := time.Now().Add(3 * time.Second)
		for r.trackedOpen() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	if err := ping(echo); err != nil {
		t.Fatal(err)
	}
	waitIdle()
	start := time.Now()
	if err := ping(closed); err == nil {
		t.Fatal("a refused destination carried data")
	} else if time.Since(start) > 3*time.Second {
		t.Fatalf("a refused destination took %v to fail", time.Since(start))
	}
	waitIdle()
	if err := ping(echo); err != nil {
		t.Fatalf("the session after a refused destination: %v", err)
	}
	if sessions := anytlsSessionsHeld(t, r); sessions != 1 {
		t.Fatalf("expected one pooled session throughout, got %d", sessions)
	}
}
