package rate_test

import (
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/juju/ratelimit"
	N "github.com/sagernet/sing/common/network"
)

type headroomPacketConn struct{ fakePacketConn }

func (*headroomPacketConn) FrontHeadroom() int { return 32 }
func (*headroomPacketConn) RearHeadroom() int  { return 16 }

func TestPacketRateLimiterCountsInnerHeadroomOnce(t *testing.T) {
	inner := &headroomPacketConn{}
	wrapped := rate.NewPacketConnRateLimiter(inner, ratelimit.NewBucketWithQuantum(time.Hour, 100, 1))
	defer wrapped.Close()
	if front, rear := N.CalculateFrontHeadroom(wrapped), N.CalculateRearHeadroom(wrapped); front != 32 || rear != 16 {
		t.Fatalf("protocol headroom duplicated: front=%d rear=%d, want 32/16", front, rear)
	}
}
