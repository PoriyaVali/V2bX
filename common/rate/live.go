package rate

import (
	"time"

	"github.com/juju/ratelimit"
)

// Waiter is implemented by both fixed buckets and live per-user limits.
type Waiter interface {
	Wait(int64)
}

// LiveLimiter resolves the current shared bucket while waiting. Polling in
// bounded intervals lets upgrades and dynamic-limit expiry release an already
// blocked connection, as well as changing the rate of its next read/write.
type LiveLimiter struct {
	bucket func() *ratelimit.Bucket
}

func NewLiveLimiter(bucket func() *ratelimit.Bucket) *LiveLimiter {
	return &LiveLimiter{bucket: bucket}
}

func (l *LiveLimiter) Wait(count int64) {
	for count > 0 {
		b := l.bucket()
		if b == nil {
			return
		}
		count -= b.TakeAvailable(count)
		if count <= 0 {
			return
		}
		delay := 50 * time.Millisecond
		if seconds := float64(count) / b.Rate(); seconds < delay.Seconds() {
			delay = time.Duration(seconds * float64(time.Second))
		}
		if delay < time.Millisecond {
			delay = time.Millisecond
		}
		time.Sleep(delay)
	}
}
