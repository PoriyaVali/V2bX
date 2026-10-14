package rate

import (
	"context"
	"net"
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
	_ = l.WaitContext(context.Background(), count)
}

// WaitContext keeps the live shared bucket, but lets a closed connection stop
// waiting for tokens without waiting for its entire remaining transfer.
func (l *LiveLimiter) WaitContext(ctx context.Context, count int64) error {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for count > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := l.bucket()
		if b == nil {
			return nil
		}
		count -= b.TakeAvailable(count)
		if count <= 0 {
			return nil
		}
		delay := 50 * time.Millisecond
		if seconds := float64(count) / b.Rate(); seconds < delay.Seconds() {
			delay = time.Duration(seconds * float64(time.Second))
		}
		if delay < time.Millisecond {
			delay = time.Millisecond
		}
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func waitWithContext(ctx context.Context, limiter Waiter, count int64) error {
	if ctx.Err() != nil {
		return net.ErrClosed
	}
	var err error
	if live, ok := limiter.(interface {
		WaitContext(context.Context, int64) error
	}); ok {
		err = live.WaitContext(ctx, count)
	} else if bucket, ok := limiter.(*ratelimit.Bucket); ok {
		// Fixed buckets stay supported, with the same token consumption and
		// close behavior as live buckets. Unknown Waiters keep their contract.
		err = NewLiveLimiter(func() *ratelimit.Bucket { return bucket }).WaitContext(ctx, count)
	} else {
		limiter.Wait(count)
	}
	if ctx.Err() != nil {
		return net.ErrClosed
	}
	return err
}
