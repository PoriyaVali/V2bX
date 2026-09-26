package limiter

import (
	"math"
	"testing"
	"time"

	"github.com/juju/ratelimit"
)

// rateIs reports whether the bucket refills at bytesPerSecond, within the 1%
// margin ratelimit.NewBucketWithRate works to.
func rateIs(b *ratelimit.Bucket, bytesPerSecond int64) bool {
	return math.Abs(b.Rate()-float64(bytesPerSecond))/float64(bytesPerSecond) <= 0.01
}

// The bucket must refill continuously. It used to hand out a whole second's
// allowance at once and then nothing until the next second, so a user at their
// limit saw a burst and a ~1 s stall every second.
func TestSpeedBucket_RefillsSmoothly(t *testing.T) {
	const limit = 5_000_000 // 40 Mbit/s, the busiest plan
	b := newSpeedBucket(limit)
	if !rateIs(b, limit) {
		t.Fatalf("rate %v, want %d", b.Rate(), limit)
	}
	if b.Capacity() > limit/5 {
		t.Fatalf("burst %d is most of a second's allowance", b.Capacity())
	}
	b.TakeAvailable(b.Capacity()) // drain the burst
	time.Sleep(50 * time.Millisecond)
	// After 50 ms roughly 250 KB should be back. The old bucket returned
	// nothing until a full second had passed.
	if got := b.Available(); got < limit/40 {
		t.Fatalf("only %d bytes back after 50ms - refill is not continuous", got)
	}
}

func TestSpeedBucket_SmallLimitStillFitsAFullRead(t *testing.T) {
	b := newSpeedBucket(125_000) // 1 Mbit/s
	if b.Capacity() < 64*1024 {
		t.Fatalf("burst %d cannot hold one full read", b.Capacity())
	}
}
