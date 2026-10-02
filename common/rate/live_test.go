package rate_test

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/juju/ratelimit"
	"github.com/sagernet/sing/common/buf"
)

func TestLiveLimiterReleasesInFlightWaitWhenLimitIsLifted(t *testing.T) {
	var current atomic.Pointer[ratelimit.Bucket]
	current.Store(ratelimit.NewBucketWithRate(1, 1))
	consulted := make(chan struct{}, 1)
	live := rate.NewLiveLimiter(func() *ratelimit.Bucket {
		select {
		case consulted <- struct{}{}:
		default:
		}
		return current.Load()
	})
	done := make(chan struct{})
	go func() { live.Wait(1_000_000); close(done) }()
	<-consulted
	select {
	case <-done:
		t.Fatal("limited wait returned before tokens were available")
	case <-time.After(20 * time.Millisecond):
	}
	current.Store(nil)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an in-flight wait kept the previous bucket after the limit was lifted")
	}
}

// Construct the wrapper while unlimited, then change its provider without
// reopening the connection. The next read must consume the newly shared bucket.
func TestEstablishedConnectionPicksUpLiveLimit(t *testing.T) {
	var current atomic.Pointer[ratelimit.Bucket]
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := rate.NewConnRateLimiter(left, rate.NewLiveLimiter(current.Load))
	bucket := ratelimit.NewBucketWithQuantum(time.Hour, 100, 1)
	current.Store(bucket)
	before := bucket.Available()
	go func() { _, _ = right.Write([]byte("hello")) }()
	buffer := make([]byte, 5)
	if _, err := conn.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if got := before - bucket.Available(); got != 5 {
		t.Fatalf("established wrapper consumed %d tokens, want 5", got)
	}
	replacement := ratelimit.NewBucketWithQuantum(time.Hour, 100, 1)
	current.Store(replacement)
	go func() { _, _ = right.Write([]byte("again")) }()
	if _, err := conn.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if got := replacement.Available(); got != 95 {
		t.Fatalf("new rate bucket has %d tokens, want 95", got)
	}
}

// UDP uses the same live provider, including when the first packet was sent
// before any limit was configured.
func TestEstablishedPacketConnectionPicksUpLiveLimit(t *testing.T) {
	var current atomic.Pointer[ratelimit.Bucket]
	conn := rate.NewPacketConnRateLimiter(&fakePacketConn{packets: 1, size: 20}, rate.NewLiveLimiter(current.Load))
	bucket := ratelimit.NewBucketWithQuantum(time.Hour, 100, 1)
	current.Store(bucket)
	buffer := buf.NewSize(64)
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); err != nil {
		t.Fatal(err)
	}
	if got := bucket.Available(); got != 80 {
		t.Fatalf("existing packet wrapper ignored new bucket: %d tokens", got)
	}
}
