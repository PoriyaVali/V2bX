package bufio

import (
	"io"
	"net"
	"net/netip"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type readFromWithBufferPacketReader interface {
	ReadFromWithBuffer(func(sizeHint int) []byte) (int, net.Addr, error)
}

type readFromUDPAddrPortWithBufferPacketReader interface {
	ReadFromUDPAddrPortWithBuffer(func(sizeHint int) []byte) (int, netip.AddrPort, error)
}

func createReadFromWithBufferPacketWaiter(reader any) (N.PacketReadWaiter, bool) {
	// ExtendedPacketConn intentionally is not ReaderReplaceable: its upstream
	// only implements net.PacketConn, not N.PacketReader. Inspect this local
	// wrapper explicitly instead of changing the generic unwrap rules.
	if source, ok := reader.(*ExtendedPacketConn); ok {
		return createReadFromWithBufferPacketWaiter(source.PacketConn)
	}

	// Prefer AddrPort for UDP so the source does not create a net.UDPAddr for
	// every packet.
	if source, ok := reader.(readFromUDPAddrPortWithBufferPacketReader); ok {
		return &udpAddrPortPacketReadWaiter{reader: source}, true
	}

	// This covers implementations that expose only the standard net.Addr form.
	if source, ok := reader.(readFromWithBufferPacketReader); ok {
		return &netAddrPacketReadWaiter{reader: source}, true
	}

	return nil, false
}

// packetReadWithBufferState contains the part shared by both packet waiters.
// It deliberately does not implement a reader interface: the two waiters
// call their source interface directly.
type packetReadWithBufferState struct {
	options N.ReadWaitOptions
	buffer  *buf.Buffer
	// Created once during initialization so packet reads reuse the callback.
	bufferForRead func(int) []byte
}

func (s *packetReadWithBufferState) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	s.options = options
	s.buffer = nil
	s.bufferForRead = func(sizeHint int) []byte {
		s.buffer = s.options.NewPacketBuffer()
		return s.buffer.FreeBytes() // This slice starts after FrontHeadroom and ends before the reserved RearHeadroom.
	}
	return false // The returned buffer already satisfies the requested headroom.
}

func (s *packetReadWithBufferState) finish(
	n int,
	destination M.Socksaddr,
	err error,
) (*buf.Buffer, M.Socksaddr, error) {
	buffer := s.buffer
	s.buffer = nil

	if err != nil {
		if buffer != nil {
			buffer.Release()
		}
		return nil, M.Socksaddr{}, err
	}

	if buffer == nil {
		// A conforming ReadFromWithBuffer implementation calls the callback
		// whenever it returns a datagram. Keep the waiter total if it does not.
		return nil, M.Socksaddr{}, io.EOF
	}

	// A zero-length datagram is a valid successful packet read.
	buffer.Truncate(n)
	s.options.PostReturn(buffer)
	return buffer, destination, nil
}

var _ N.PacketReadWaiter = (*udpAddrPortPacketReadWaiter)(nil)

type udpAddrPortPacketReadWaiter struct {
	reader readFromUDPAddrPortWithBufferPacketReader
	packetReadWithBufferState
}

func (w *udpAddrPortPacketReadWaiter) WaitReadPacket() (
	buffer *buf.Buffer,
	destination M.Socksaddr,
	err error,
) {
	n, address, err := w.reader.ReadFromUDPAddrPortWithBuffer(w.bufferForRead)
	return w.finish(n, M.SocksaddrFromNetIP(address).Unwrap(), err)
}

var _ N.PacketReadWaiter = (*netAddrPacketReadWaiter)(nil)

type netAddrPacketReadWaiter struct {
	reader readFromWithBufferPacketReader
	packetReadWithBufferState
}

func (w *netAddrPacketReadWaiter) WaitReadPacket() (
	buffer *buf.Buffer,
	destination M.Socksaddr,
	err error,
) {
	n, address, err := w.reader.ReadFromWithBuffer(w.bufferForRead)
	return w.finish(n, M.SocksaddrFromNet(address).Unwrap(), err)
}
