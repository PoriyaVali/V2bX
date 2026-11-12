package dispatcher

import (
	"context"
	"io"
	"sync/atomic"
	"time"

	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/xtls/xray-core/common/buf"
)

var _ buf.TimeoutReader = (*CounterReader)(nil)

// CounterReader counts what a user uploads through a DispatchLink link, and
// holds it to the user's speed limit.
type CounterReader struct {
	Reader  buf.TimeoutReader
	Counter *atomic.Int64
	// Limiter is the user's speed limit; nil for none. What was read waits
	// for it before it goes on, so the inbound is read no faster. Context
	// ends the wait with the link.
	Limiter rate.Waiter
	Context context.Context
}

// ReadMultiBufferTimeout waits no longer than the caller asked. Sniffing gives
// the first read what is left of its 200 ms budget; a fixed second here made
// every connection whose server speaks first (SSH, SMTP, many games) wait a
// full second on a VLESS node before its first byte.
func (c *CounterReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb, err := c.Reader.ReadMultiBufferTimeout(timeout)
	return c.counted(mb, err)
}

func (c *CounterReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := c.Reader.ReadMultiBuffer()
	return c.counted(mb, err)
}

func (c *CounterReader) counted(mb buf.MultiBuffer, err error) (buf.MultiBuffer, error) {
	size := int64(mb.Len())
	if size == 0 {
		return mb, err
	}
	c.Counter.Add(size)
	if c.Limiter == nil {
		return mb, err
	}
	ctx := c.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if rate.Wait(ctx, c.Limiter, size) != nil {
		// The link ended while this waited its turn.
		buf.ReleaseMulti(mb)
		return nil, io.ErrClosedPipe
	}
	return mb, err
}
