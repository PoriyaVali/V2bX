package canceler

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// busyPacketConn reads and writes packets as fast as it is asked to, with a
// read waiter, as a Hysteria2 session's UDP conn does.
type busyPacketConn struct {
	N.PacketConn
	reads int
	limit int
}

func (c *busyPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	if c.reads++; c.reads > c.limit {
		return M.Socksaddr{}, io.EOF
	}
	_, _ = b.WriteString("ping")
	return M.ParseSocksaddr("1.1.1.1:53"), nil
}

func (c *busyPacketConn) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	b.Release()
	return nil
}

func (c *busyPacketConn) SetReadDeadline(time.Time) error { return nil }

func (c *busyPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (c *busyPacketConn) Close() error { return nil }

type busyReadWaiter struct{ *busyPacketConn }

func (w busyReadWaiter) InitializeReadWaiter(N.ReadWaitOptions) bool { return false }

func (w busyReadWaiter) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	b := buf.NewPacket()
	destination, err := w.ReadPacket(b)
	if err != nil {
		b.Release()
		return nil, M.Socksaddr{}, err
	}
	return b, destination, nil
}

func (c *busyPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	return busyReadWaiter{c}, true
}

// A session's reader notes activity on every packet it reads while another
// goroutine writes the replies, each noting activity too. mihomo's
// listener reads a Hysteria2 session with the read waiter on one goroutine
// while its tunnel writes back on another; the activity time was written by
// both with no lock (run with -race).
func TestTimeoutPacketConnReadAndWriteConcurrently(t *testing.T) {
	for _, waiter := range []bool{false, true} {
		_, conn := NewTimeoutPacketConn(context.Background(), &busyPacketConn{limit: 2000}, time.Minute)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if waiter {
				rw, ok := conn.(*TimeoutPacketConn).CreateReadWaiter()
				if !ok {
					t.Error("no read waiter")
					return
				}
				for {
					b, _, err := rw.WaitReadPacket()
					if err != nil {
						return
					}
					b.Release()
				}
			}
			for {
				b := buf.NewPacket()
				_, err := conn.ReadPacket(b)
				b.Release()
				if err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				b := buf.NewPacket()
				_, _ = b.WriteString("pong")
				_ = conn.WritePacket(b, M.ParseSocksaddr("1.1.1.1:53"))
			}
		}()
		wg.Wait()
		if conn.(*TimeoutPacketConn).Timeout() != time.Minute {
			t.Fatal("timeout changed")
		}
	}
}
