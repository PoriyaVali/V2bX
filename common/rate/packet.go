package rate

import (
	"github.com/juju/ratelimit"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// PacketConn applies a user's speed limit to UDP, sharing the bucket their TCP
// connections draw from.
//
// UDP used to go unlimited: the hook built the bucket and then left the
// wrapping line commented out, so a subscriber on a speed-limited plan was
// held to it over TCP only - QUIC (YouTube, Instagram, Google) and voice/video
// calls ran at full speed.
//
// It deliberately does NOT declare Upstream or the unwrap interfaces. Those
// would let sing's copy loop reach past this wrapper to the raw connection,
// which is exactly how a limiter ends up in the chain and never consulted.
// The headroom the inner connection needs is still reported, so buffers are
// sized for it and nothing is copied to make room.
type PacketConn struct {
	N.PacketConn
	limiter *ratelimit.Bucket
}

func NewPacketConnRateLimiter(c N.PacketConn, l *ratelimit.Bucket) N.PacketConn {
	return &PacketConn{PacketConn: c, limiter: l}
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err == nil && buffer.Len() > 0 {
		c.limiter.Wait(int64(buffer.Len()))
	}
	return destination, err
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if n := buffer.Len(); n > 0 {
		c.limiter.Wait(int64(n))
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *PacketConn) FrontHeadroom() int { return N.CalculateFrontHeadroom(c.PacketConn) }

func (c *PacketConn) RearHeadroom() int { return N.CalculateRearHeadroom(c.PacketConn) }
