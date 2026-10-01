package rate

import "net"

func NewConnRateLimiter(c net.Conn, l Waiter) *Conn {
	return &Conn{
		Conn:    c,
		limiter: l,
	}
}

type Conn struct {
	net.Conn
	limiter Waiter
}

func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.limiter.Wait(int64(n))
	}
	return n, err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.limiter.Wait(int64(n))
	}
	return n, err
}
