//go:build soak

package sing

import (
	"io"
	"net"
	"testing"
	"time"
)

// AnyTLS v2 closes a reused session unless the server acknowledges its new
// stream within three seconds, even if the destination has no data to send.
func TestAnytlsReusedSessionAcknowledgesSilentDestination(t *testing.T) {
	r := startSoakRig(t)
	echo := listen(t, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) })
	first, err := socksConnect(r.socksPort, echo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(first, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	// Allow the client's close hook to return this session to its reuse pool.
	time.Sleep(100 * time.Millisecond)
	quiet := listen(t, func(c net.Conn) {
		defer c.Close()
		time.Sleep(4200 * time.Millisecond)
		_, _ = c.Write([]byte("still-connected"))
	})
	second, err := socksConnect(r.socksPort, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	start := time.Now()
	payload := make([]byte, len("still-connected"))
	if _, err = io.ReadFull(second, payload); err != nil {
		t.Fatalf("reused AnyTLS stream closed after %v before destination replied: %v", time.Since(start), err)
	}
	if string(payload) != "still-connected" {
		t.Fatalf("unexpected response: %q", payload)
	}
}
