package rate_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/juju/ratelimit"
	N "github.com/sagernet/sing/common/network"
)

type handshakeConn struct {
	net.Conn
	success bool
	failure error
}

func (c *handshakeConn) HandshakeSuccess() error          { c.success = true; return nil }
func (c *handshakeConn) HandshakeFailure(err error) error { c.failure = err; return nil }

func TestRateConnPreservesHandshakeWithoutUnwrappingData(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	inner := &handshakeConn{Conn: left}
	limited := rate.NewConnRateLimiter(inner, ratelimit.NewBucketWithQuantum(time.Hour, 100, 1))
	defer limited.Close()
	wrapped := counter.NewConnCounter(limited, &counter.TrafficStorage{})
	if err := N.ReportConnHandshakeSuccess(wrapped, right); err != nil || !inner.success {
		t.Fatalf("handshake success did not reach inner connection: %v", err)
	}
	failure := errors.New("destination unreachable")
	_ = N.ReportHandshakeFailure(wrapped, failure)
	if inner.failure != failure {
		t.Fatal("handshake failure did not reach inner connection")
	}
	reader, reads := N.UnwrapCountReader(wrapped, nil)
	writer, writes := N.UnwrapCountWriter(wrapped, nil)
	if reader != limited || writer != limited || len(reads) != 1 || len(writes) != 1 {
		t.Fatal("data path bypassed the speed limiter")
	}
}

type handshakePacketConn struct {
	fakePacketConn
	success bool
	failure error
}

func (c *handshakePacketConn) HandshakeSuccess() error          { c.success = true; return nil }
func (c *handshakePacketConn) HandshakeFailure(err error) error { c.failure = err; return nil }

func TestRatePacketConnPreservesHandshakeWithoutUnwrappingData(t *testing.T) {
	inner := &handshakePacketConn{}
	limited := rate.NewPacketConnRateLimiter(inner, ratelimit.NewBucketWithQuantum(time.Hour, 100, 1))
	defer limited.Close()
	wrapped := counter.NewPacketConnCounter(limited, &counter.TrafficStorage{})
	if err := N.ReportPacketConnHandshakeSuccess(wrapped, nil); err != nil || !inner.success {
		t.Fatalf("packet handshake success did not reach inner connection: %v", err)
	}
	failure := errors.New("destination unreachable")
	_ = N.ReportHandshakeFailure(wrapped, failure)
	if inner.failure != failure {
		t.Fatal("packet handshake failure did not reach inner connection")
	}
	reader, reads := N.UnwrapCountPacketReader(wrapped, nil)
	writer, writes := N.UnwrapCountPacketWriter(wrapped, nil)
	if reader != limited || writer != limited || len(reads) != 1 || len(writes) != 1 {
		t.Fatal("packet data path bypassed the speed limiter")
	}
}
