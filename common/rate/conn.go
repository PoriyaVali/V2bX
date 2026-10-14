package rate

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func NewConnRateLimiter(c net.Conn, l Waiter) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &Conn{Conn: c, limiter: l, ctx: ctx, cancel: cancel}
	// Detach sniffed data before the copy and close goroutines start. CachedConn
	// does not synchronize plain Read with Close; hiding its CachedReader
	// interface would leave its buffer in that unsafe path.
	reader := N.UnwrapReader(c)
	for {
		cached, ok := reader.(N.CachedReader)
		if !ok {
			break
		}
		buffer := cached.ReadCached()
		if buffer == nil {
			break
		}
		if buffer.Len() > 0 {
			conn.cached = append(conn.cached, buffer.ToOwned())
		}
		buffer.Release()
		reader = N.UnwrapReader(reader)
	}
	return conn
}

type Conn struct {
	net.Conn
	limiter Waiter
	ctx     context.Context
	cancel  context.CancelFunc
	cacheMu sync.Mutex
	cached  []*buf.Buffer
}

// Control interfaces (such as AnyTLS handshake acknowledgements) must remain
// discoverable through common.Cast. Reads and writes must still pass through
// this wrapper, including when the current live limit is unlimited.
func (c *Conn) Upstream() any { return c.Conn }

func (c *Conn) ReaderReplaceable() bool { return false }

func (c *Conn) WriterReplaceable() bool { return false }

func (c *Conn) ReadCached() *buf.Buffer {
	c.cacheMu.Lock()
	if len(c.cached) == 0 {
		c.cacheMu.Unlock()
		return nil
	}
	buffer := c.cached[0]
	c.cached[0] = nil
	c.cached = c.cached[1:]
	c.cacheMu.Unlock()
	if err := waitWithContext(c.ctx, c.limiter, int64(buffer.Len())); err != nil {
		buffer.Release()
		return nil
	}
	return buffer
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	c.cacheMu.Lock()
	if len(c.cached) > 0 {
		buffer := c.cached[0]
		n, err = buffer.Read(b)
		if buffer.IsEmpty() {
			buffer.Release()
			c.cached[0] = nil
			c.cached = c.cached[1:]
		}
		c.cacheMu.Unlock()
		if n > 0 {
			if waitErr := waitWithContext(c.ctx, c.limiter, int64(n)); waitErr != nil {
				err = waitErr
			}
		}
		return n, err
	}
	c.cacheMu.Unlock()
	n, err = c.Conn.Read(b)
	if n > 0 {
		if waitErr := waitWithContext(c.ctx, c.limiter, int64(n)); waitErr != nil {
			err = waitErr
		}
	}
	return n, err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	n, err = c.Conn.Write(b)
	if n > 0 {
		if waitErr := waitWithContext(c.ctx, c.limiter, int64(n)); waitErr != nil {
			err = waitErr
		}
	}
	return n, err
}

func (c *Conn) Close() error {
	c.cancel()
	c.cacheMu.Lock()
	for _, buffer := range c.cached {
		buffer.Release()
	}
	c.cached = nil
	c.cacheMu.Unlock()
	return c.Conn.Close()
}
