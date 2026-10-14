package rate_test

import (
	"bytes"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/juju/ratelimit"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common"
	xbuf "github.com/xtls/xray-core/common/buf"
)

func blockedLiveLimiter() (*rate.LiveLimiter, <-chan struct{}, func()) {
	var bucket atomic.Pointer[ratelimit.Bucket]
	bucket.Store(ratelimit.NewBucketWithRate(1, 1))
	consulted := make(chan struct{}, 1)
	return rate.NewLiveLimiter(func() *ratelimit.Bucket {
		select {
		case consulted <- struct{}{}:
		default:
		}
		return bucket.Load()
	}), consulted, func() { bucket.Store(nil) }
}

// Restoring unlimited mode also cleans up the goroutine on the broken source,
// so this regression can fail without leaking a minutes-long waiter.
func requireStoppedWait(t *testing.T, result <-chan error, release func()) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed transfer returned %v, want net.ErrClosed", err)
		}
	case <-time.After(300 * time.Millisecond):
		release()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("waiter did not stop even after lifting the limit")
		}
		t.Fatal("Close left the transfer blocked in its speed limiter")
	}
}

func TestRateConnCloseInterruptsLiveWait(t *testing.T) {
	for _, direction := range []string{"read", "write", "cached"} {
		t.Run(direction, func(t *testing.T) {
			live, consulted, release := blockedLiveLimiter()
			defer release()
			left, right := net.Pipe()
			defer right.Close()
			var source net.Conn = left
			if direction == "cached" {
				prefix := buf.NewSize(100)
				prefix.Extend(100)
				source = bufio.NewCachedConn(left, prefix)
			}
			conn := rate.NewConnRateLimiter(source, live)
			defer conn.Close()
			result := make(chan error, 1)
			go func() {
				var err error
				if direction == "write" {
					_, err = conn.Write(make([]byte, 100))
				} else {
					_, err = conn.Read(make([]byte, 100))
				}
				result <- err
			}()
			if direction == "write" {
				_, _ = right.Read(make([]byte, 100))
			} else if direction == "read" {
				_, _ = right.Write(make([]byte, 100))
			}
			<-consulted
			_ = conn.Close()
			requireStoppedWait(t, result, release)
		})
	}
}

func TestRatePacketCloseInterruptsLiveWait(t *testing.T) {
	for _, direction := range []string{"read", "write"} {
		t.Run(direction, func(t *testing.T) {
			live, consulted, release := blockedLiveLimiter()
			defer release()
			inner := &fakePacketConn{packets: 1, size: 100}
			conn := rate.NewPacketConnRateLimiter(inner, live)
			defer conn.Close()
			buffer := buf.NewSize(100)
			if direction == "write" {
				buffer.Extend(100)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if direction == "write" {
					err = conn.WritePacket(buffer, M.ParseSocksaddr("1.1.1.1:443"))
				} else {
					_, err = conn.ReadPacket(buffer)
				}
				result <- err
			}()
			<-consulted
			_ = conn.Close()
			requireStoppedWait(t, result, release)
			if direction == "read" {
				buffer.Release()
			} else if inner.written != 0 {
				t.Fatal("closed UDP write reached the destination")
			} else if !buffer.IsEmpty() {
				t.Fatal("canceled UDP write did not release its owned buffer")
			}
		})
	}
}

func TestCachedCopyCloseInterruptsLiveWait(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			live, consulted, release := blockedLiveLimiter()
			defer release()
			prefix := buf.NewSize(100)
			prefix.Extend(100)
			result := make(chan error, 1)
			var closeConn func() error
			var received func() int
			if transport == "tcp" {
				left, right := net.Pipe()
				defer right.Close()
				conn := rate.NewConnRateLimiter(bufio.NewCachedConn(left, prefix), live)
				closeConn = conn.Close
				var destination bytes.Buffer
				received = destination.Len
				go func() { _, err := bufio.Copy(&destination, conn); result <- err }()
			} else {
				source := bufio.NewCachedPacketConn(&fakePacketConn{}, prefix, M.ParseSocksaddr("1.1.1.1:443"))
				conn := rate.NewPacketConnRateLimiter(source, live)
				closeConn = conn.Close
				destination := &fakePacketConn{}
				received = func() int { return destination.written }
				go func() { _, err := bufio.CopyPacket(destination, conn); result <- err }()
			}
			defer closeConn()
			<-consulted
			_ = closeConn()
			requireStoppedWait(t, result, release)
			if received() != 0 {
				t.Fatal("canceled cached copy forwarded its prefix after Close")
			}
		})
	}
}

func TestFixedBucketCloseInterruptsWait(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	conn := rate.NewConnRateLimiter(left, ratelimit.NewBucketWithRate(1, 1))
	result := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 100)); result <- err }()
	_, _ = right.Write(make([]byte, 100))
	_ = conn.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed fixed bucket returned %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("fixed bucket wait did not stop on Close")
	}
}

type closingMultiWriter struct {
	written     atomic.Int64
	closed      atomic.Bool
	interrupted atomic.Bool
}

func (w *closingMultiWriter) WriteMultiBuffer(mb xbuf.MultiBuffer) error {
	w.written.Add(int64(mb.Len()))
	xbuf.ReleaseMulti(mb)
	return nil
}
func (w *closingMultiWriter) Close() error { w.closed.Store(true); return nil }
func (w *closingMultiWriter) Interrupt()   { w.interrupted.Store(true) }

func TestRateWriterCloseInterruptsLiveWait(t *testing.T) {
	for _, stop := range []string{"close", "interrupt"} {
		t.Run(stop, func(t *testing.T) {
			live, consulted, release := blockedLiveLimiter()
			defer release()
			inner := &closingMultiWriter{}
			writer := rate.NewRateLimitWriter(inner, live)
			mb := xbuf.MultiBuffer{xbuf.New()}
			_, _ = mb[0].Write(make([]byte, 100))
			result := make(chan error, 1)
			go func() { result <- writer.WriteMultiBuffer(mb) }()
			<-consulted
			if stop == "interrupt" {
				_ = common.Interrupt(writer)
			} else {
				_ = common.Close(writer)
			}
			requireStoppedWait(t, result, release)
			if inner.written.Load() != 0 || mb[0] != nil {
				t.Fatal("canceled writer forwarded data or did not release its MultiBuffer")
			}
			if stop == "interrupt" && !inner.interrupted.Load() {
				t.Fatal("Interrupt was not forwarded to the underlying writer")
			}
		})
	}
}
