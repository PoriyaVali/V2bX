package rate_test

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/juju/ratelimit"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func TestCachedTCPBytesAreLimitedAndCountedOnce(t *testing.T) {
	left, right := net.Pipe()
	_ = right.Close()
	first, second := buf.NewSize(64), buf.NewSize(64)
	_, _ = first.Write([]byte("body"))
	_, _ = second.Write([]byte("header"))
	source := bufio.NewCachedConn(bufio.NewCachedConn(left, first), second)
	bucket := ratelimit.NewBucketWithQuantum(time.Hour, 100, 1)
	storage := &counter.TrafficStorage{}
	limited := rate.NewConnRateLimiter(source, bucket)
	defer limited.Close()
	conn := counter.NewConnCounter(limited, storage)
	var destination bytes.Buffer
	if _, err := bufio.Copy(&destination, conn); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if got := destination.String(); got != "headerbody" {
		t.Fatalf("cached prefix order changed: %q", got)
	}
	if used := 100 - bucket.Available(); used != 10 {
		t.Fatalf("cached bytes used %d tokens, want 10", used)
	}
	if got := storage.UpCounter.Load(); got != 10 {
		t.Fatalf("cached bytes billed %d, want 10", got)
	}
}

func TestCachedTCPReadIsSafeAgainstConcurrentClose(t *testing.T) {
	for i := 0; i < 300; i++ {
		left, right := net.Pipe()
		buffer := buf.NewSize(4096)
		_, _ = buffer.Write(make([]byte, 4096))
		conn := rate.NewConnRateLimiter(bufio.NewCachedConn(left, buffer),
			rate.NewLiveLimiter(func() *ratelimit.Bucket { return nil }))
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			_, _ = conn.Read(make([]byte, 1))
		}()
		go func() {
			defer group.Done()
			<-start
			_ = conn.Close()
		}()
		close(start)
		group.Wait()
		_ = right.Close()
	}
}

func TestCachedPacketBytesAreLimitedAndCountedOnce(t *testing.T) {
	buffer := buf.NewSize(64)
	_, _ = buffer.Write([]byte("packet"))
	cached := bufio.NewCachedPacketConn(&fakePacketConn{}, buffer, M.ParseSocksaddr("1.1.1.1:443"))
	bucket := ratelimit.NewBucketWithQuantum(time.Hour, 100, 1)
	storage := &counter.TrafficStorage{}
	conn := counter.NewPacketConnCounter(rate.NewPacketConnRateLimiter(cached, bucket), storage)
	defer conn.Close()
	destination := &fakePacketConn{}
	if _, err := bufio.CopyPacket(destination, conn); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if destination.written != 6 || storage.UpCounter.Load() != 6 || bucket.Available() != 94 {
		t.Fatalf("cached packet: written=%d counted=%d tokens=%d",
			destination.written, storage.UpCounter.Load(), bucket.Available())
	}
}

func TestCachedPacketReadIsSafeAgainstConcurrentClose(t *testing.T) {
	for i := 0; i < 300; i++ {
		buffer := buf.NewSize(64)
		_, _ = buffer.Write([]byte("packet"))
		cached := bufio.NewCachedPacketConn(&fakePacketConn{}, buffer, M.ParseSocksaddr("1.1.1.1:443"))
		conn := rate.NewPacketConnRateLimiter(cached,
			rate.NewLiveLimiter(func() *ratelimit.Bucket { return nil }))
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			out := buf.NewSize(64)
			defer out.Release()
			_, _ = conn.ReadPacket(out)
		}()
		go func() {
			defer group.Done()
			<-start
			_ = conn.Close()
		}()
		close(start)
		group.Wait()
	}
}
