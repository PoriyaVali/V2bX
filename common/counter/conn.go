package counter

import (
	"io"
	"net"

	"github.com/sagernet/sing/common/bufio"

	"github.com/sagernet/sing/common/buf"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

type ConnCounter struct {
	network.ExtendedConn
	storages  []*TrafficStorage
	readFunc  network.CountFunc
	writeFunc network.CountFunc
}

// NewConnCounter counts this connection into every storage given.
//
// Variadic so one wrapper can feed several ledgers at once - today the user's
// total and, alongside it, that user's per-source-address total. Stacking two
// ConnCounters would look equivalent and is not: each declares its upstream
// replaceable and hands out its own CountFunc through UnwrapReader/UnwrapWriter,
// so sing may take the inner one and skip the outer entirely. That failure is
// silent - data keeps flowing, one of the ledgers just stays at zero - which is
// exactly the shape of bug that cost a release to notice before. Counting both
// from a single wrapper removes the question.
func NewConnCounter(conn net.Conn, s ...*TrafficStorage) net.Conn {
	storages := append([]*TrafficStorage(nil), s...)
	return &ConnCounter{
		ExtendedConn: bufio.NewExtendedConn(conn),
		storages:     storages,
		readFunc: func(n int64) {
			for _, st := range storages {
				st.UpCounter.Add(n)
			}
		},
		writeFunc: func(n int64) {
			for _, st := range storages {
				st.DownCounter.Add(n)
			}
		},
	}
}

func (c *ConnCounter) addUp(n int64) {
	for _, st := range c.storages {
		st.UpCounter.Add(n)
	}
}

func (c *ConnCounter) addDown(n int64) {
	for _, st := range c.storages {
		st.DownCounter.Add(n)
	}
}

// Add, not Store. These two used Store, which REPLACES the running total with
// the size of the last read or write instead of adding to it - so a connection
// that moved 300 bytes in three calls reported 100. Every other path here
// (ReadBuffer, WriteBuffer, and the CountFuncs handed out by UnwrapReader and
// UnwrapWriter) already accumulates correctly, which is why billing has held up:
// ConnCounter is an ExtendedConn, so sing's copy path prefers those. That also
// made this harmless enough to survive - it was inherited with the file rather
// than written here - but it is a mine for any caller that treats the counter as
// a plain net.Conn, whose traffic would silently go almost entirely uncounted.
func (c *ConnCounter) Read(b []byte) (n int, err error) {
	n, err = c.ExtendedConn.Read(b)
	if n > 0 {
		c.addUp(int64(n))
	}
	return
}

func (c *ConnCounter) Write(b []byte) (n int, err error) {
	n, err = c.ExtendedConn.Write(b)
	if n > 0 {
		c.addDown(int64(n))
	}
	return
}

func (c *ConnCounter) ReadBuffer(buffer *buf.Buffer) error {
	err := c.ExtendedConn.ReadBuffer(buffer)
	if err != nil {
		return err
	}
	if buffer.Len() > 0 {
		c.addUp(int64(buffer.Len()))
	}
	return nil
}

func (c *ConnCounter) WriteBuffer(buffer *buf.Buffer) error {
	dataLen := int64(buffer.Len())
	err := c.ExtendedConn.WriteBuffer(buffer)
	if err != nil {
		return err
	}
	if dataLen > 0 {
		c.addDown(dataLen)
	}
	return nil
}

func (c *ConnCounter) UnwrapReader() (io.Reader, []network.CountFunc) {
	return c.ExtendedConn, []network.CountFunc{
		c.readFunc,
	}
}

func (c *ConnCounter) UnwrapWriter() (io.Writer, []network.CountFunc) {
	return c.ExtendedConn, []network.CountFunc{
		c.writeFunc,
	}
}

func (c *ConnCounter) Upstream() any {
	return c.ExtendedConn
}

type PacketConnCounter struct {
	network.PacketConn
	storages  []*TrafficStorage
	readFunc  network.CountFunc
	writeFunc network.CountFunc
}

// Variadic for the same reason as NewConnCounter: one wrapper, several ledgers.
// UDP counts here too - the limiter registers a source address for packet
// connections as well, so leaving them out would make a UDP-only device look
// like it moved no traffic at all.
func NewPacketConnCounter(conn network.PacketConn, s ...*TrafficStorage) network.PacketConn {
	storages := append([]*TrafficStorage(nil), s...)
	return &PacketConnCounter{
		PacketConn: conn,
		storages:   storages,
		readFunc: func(n int64) {
			for _, st := range storages {
				st.UpCounter.Add(n)
			}
		},
		writeFunc: func(n int64) {
			for _, st := range storages {
				st.DownCounter.Add(n)
			}
		},
	}
}

func (p *PacketConnCounter) ReadPacket(buff *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = p.PacketConn.ReadPacket(buff)
	if err != nil {
		return
	}
	if n := int64(buff.Len()); n > 0 {
		for _, st := range p.storages {
			st.UpCounter.Add(n)
		}
	}
	return
}

func (p *PacketConnCounter) WritePacket(buff *buf.Buffer, destination M.Socksaddr) (err error) {
	n := int64(buff.Len())
	err = p.PacketConn.WritePacket(buff, destination)
	if err != nil {
		return
	}
	if n > 0 {
		for _, st := range p.storages {
			st.DownCounter.Add(n)
		}
	}
	return
}

func (p *PacketConnCounter) UnwrapPacketReader() (network.PacketReader, []network.CountFunc) {
	return p.PacketConn, []network.CountFunc{
		p.readFunc,
	}
}

func (p *PacketConnCounter) UnwrapPacketWriter() (network.PacketWriter, []network.CountFunc) {
	return p.PacketConn, []network.CountFunc{
		p.writeFunc,
	}
}

func (p *PacketConnCounter) Upstream() any {
	return p.PacketConn
}
