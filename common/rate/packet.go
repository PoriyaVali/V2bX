package rate

import (
	"sync"

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
	limiter Waiter
	cacheMu sync.Mutex
	cached  []*N.PacketBuffer
}

func NewPacketConnRateLimiter(c N.PacketConn, l Waiter) N.PacketConn {
	conn := &PacketConn{PacketConn: c, limiter: l}
	reader := N.UnwrapPacketReader(c)
	for {
		cached, ok := reader.(N.CachedPacketReader)
		if !ok {
			break
		}
		packet := cached.ReadCachedPacket()
		if packet == nil {
			break
		}
		if packet.Buffer != nil {
			owned := N.NewPacketBuffer()
			*owned = N.PacketBuffer{Buffer: packet.Buffer.ToOwned(), Destination: packet.Destination}
			conn.cached = append(conn.cached, owned)
			packet.Buffer.Release()
		}
		N.PutPacketBuffer(packet)
		reader = N.UnwrapPacketReader(reader)
	}
	return conn
}

// ReadCachedPacket preserves sing's cached-packet copy path while charging the
// current bucket exactly once. Close cannot release a packet already returned.
func (c *PacketConn) ReadCachedPacket() *N.PacketBuffer {
	c.cacheMu.Lock()
	if len(c.cached) == 0 {
		c.cacheMu.Unlock()
		return nil
	}
	packet := c.cached[0]
	c.cached[0] = nil
	c.cached = c.cached[1:]
	c.cacheMu.Unlock()
	c.limiter.Wait(int64(packet.Buffer.Len()))
	return packet
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if packet := c.ReadCachedPacket(); packet != nil {
		destination := packet.Destination
		_, err := buffer.ReadOnceFrom(packet.Buffer)
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
		return destination, err
	}
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

func (c *PacketConn) Close() error {
	c.cacheMu.Lock()
	N.ReleaseMultiPacketBuffer(c.cached)
	c.cached = nil
	c.cacheMu.Unlock()
	return c.PacketConn.Close()
}
