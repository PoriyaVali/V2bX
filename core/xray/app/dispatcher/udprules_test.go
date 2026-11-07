package dispatcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/pipe"
)

func datagram(payload string, to *net.Destination) *buf.Buffer {
	b := buf.New()
	_, _ = b.WriteString(payload)
	b.UDP = to
	return b
}

func udpDestination(addr string, port uint16) *net.Destination {
	d := net.UDPDestination(net.ParseAddress(addr), net.Port(port))
	return &d
}

// The panel's rules apply to each datagram of a full-cone UDP session, which
// names its own destination in b.UDP, not only to the destination the
// session opened with. A refused datagram is dropped and the session reads
// on, a datagram with no destination of its own goes where the session goes,
// and the pipe behind is still interrupted through the filter.
func TestUDPRuleReaderChecksEveryDatagram(t *testing.T) {
	l := &limiter.Limiter{}
	if err := l.UpdateRule(&panel.Rules{Regexp: []string{`blocked\.example`}, Port: []string{"9999"}, IP: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	first := udpDestination("1.1.1.1", 443)
	reader, writer := pipe.New()
	r := newUDPRuleReader(context.Background(), reader, l, "user", *first, *first)
	go func() {
		_ = writer.WriteMultiBuffer(buf.MultiBuffer{
			datagram("first", first),
			datagram("blocked port", udpDestination("8.8.8.8", 9999)),
			datagram("public", udpDestination("8.8.8.8", 53)),
		})
		_ = writer.WriteMultiBuffer(buf.MultiBuffer{
			datagram("blocked address", udpDestination("10.1.2.3", 53)),
			datagram("blocked name", udpDestination("blocked.example", 53)),
		})
		_ = writer.WriteMultiBuffer(buf.MultiBuffer{
			datagram("session's own", nil),
			datagram("other name", udpDestination("example.com", 53)),
		})
	}()
	var got []string
	for len(got) < 4 {
		mb, err := r.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if mb.IsEmpty() {
			t.Fatal("a read returned nothing, with no error")
		}
		for _, b := range mb {
			got = append(got, b.String())
		}
		buf.ReleaseMulti(mb)
	}
	want := []string{"first", "public", "session's own", "other name"}
	if len(got) != len(want) {
		t.Fatalf("went on %q, want %q", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("went on %q, want %q", got, want)
		}
	}

	// Only refused datagrams within the timeout: a timeout, not an empty read.
	_ = writer.WriteMultiBuffer(buf.MultiBuffer{datagram("blocked port", udpDestination("8.8.8.8", 9999))})
	if mb, err := r.ReadMultiBufferTimeout(100 * time.Millisecond); !errors.Is(err, buf.ErrReadTimeout) || !mb.IsEmpty() {
		t.Fatalf("read %v, %v; want a timeout", mb, err)
	}

	r.Interrupt()
	if _, err := reader.ReadMultiBuffer(); err == nil {
		t.Fatal("Interrupt did not reach the pipe")
	}
}
