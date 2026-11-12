package rate_test

import (
	"net"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// Bytes a limited connection delivered are billed even when the connection
// closes while the write still waits for the user's allowance. The write was
// reported as failed then, and a caller that takes a buffer as written or
// not, as the counter in front of AnyTLS and gRPC streams does, dropped it:
// under a speed limit the end of every download was delivered and not
// billed, 18 KiB of 512 in the served-node survey.
func TestBytesDeliveredBeforeCloseAreCounted(t *testing.T) {
	live, consulted, release := blockedLiveLimiter()
	defer release()
	left, right := net.Pipe()
	defer right.Close()
	var billed counter.TrafficStorage
	conn := counter.NewConnCounter(rate.NewConnRateLimiter(left, live), &billed)
	written := make(chan error, 1)
	go func() {
		buffer := buf.NewSize(100)
		buffer.Extend(100)
		written <- conn.(N.ExtendedConn).WriteBuffer(buffer)
	}()
	received := make([]byte, 100)
	if n, err := right.Read(received); n != 100 || err != nil {
		t.Fatalf("the peer read %d bytes, %v", n, err)
	}
	<-consulted
	_ = conn.Close()
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("Close left the write waiting in its speed limiter")
	}
	if got := billed.DownCounter.Load(); got != 100 {
		t.Fatalf("billed %d of the 100 bytes the peer received", got)
	}
}
