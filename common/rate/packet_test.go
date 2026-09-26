package rate_test

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/juju/ratelimit"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

// fakePacketConn yields `packets` packets of `size` bytes, then EOF, and
// swallows writes.
type fakePacketConn struct {
	mu      sync.Mutex
	packets int
	size    int
	written int
}

func (f *fakePacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.packets == 0 {
		return M.Socksaddr{}, io.EOF
	}
	f.packets--
	b.Extend(f.size)
	return M.ParseSocksaddr("1.1.1.1:443"), nil
}

func (f *fakePacketConn) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	f.mu.Lock()
	f.written += b.Len()
	f.mu.Unlock()
	b.Release()
	return nil
}

func (f *fakePacketConn) Close() error                     { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// sing's copy loop unwraps connections to reach the raw one. The limiter must
// stay in the path when it sits under the traffic counter, exactly as the hook
// stacks them - otherwise it is wired in and never consulted.
func TestPacketRateLimiter_StaysInSingCopyPath(t *testing.T) {
	const packets, size = 10, 100
	src := &fakePacketConn{packets: packets, size: size}
	dst := &fakePacketConn{}
	// Huge capacity, negligible refill: whatever the copy takes shows up as a
	// drop in Available.
	bucket := ratelimit.NewBucketWithQuantum(time.Hour, 1<<20, 1)
	before := bucket.Available()

	storage := &counter.TrafficStorage{}
	conn := counter.NewPacketConnCounter(rate.NewPacketConnRateLimiter(src, bucket), storage)

	if _, err := bufio.CopyPacket(dst, conn); err != nil && err != io.EOF {
		t.Fatalf("copy: %v", err)
	}
	if taken := before - bucket.Available(); taken != packets*size {
		t.Fatalf("limiter consulted for %d bytes, want %d - the copy went around it", taken, packets*size)
	}
	if got := storage.UpCounter.Load(); got != packets*size {
		t.Fatalf("counter saw %d bytes, want %d", got, packets*size)
	}
	if dst.written != packets*size {
		t.Fatalf("destination got %d bytes, want %d", dst.written, packets*size)
	}
}

// Writes are limited too, from the same bucket.
func TestPacketRateLimiter_WritesDrawOnTheBucket(t *testing.T) {
	inner := &fakePacketConn{}
	bucket := ratelimit.NewBucketWithQuantum(time.Hour, 1<<20, 1)
	before := bucket.Available()
	pc := rate.NewPacketConnRateLimiter(inner, bucket)
	b := buf.New()
	b.Extend(500)
	if err := pc.WritePacket(b, M.ParseSocksaddr("1.1.1.1:53")); err != nil {
		t.Fatal(err)
	}
	if taken := before - bucket.Available(); taken != 500 {
		t.Fatalf("write took %d tokens, want 500", taken)
	}
}
