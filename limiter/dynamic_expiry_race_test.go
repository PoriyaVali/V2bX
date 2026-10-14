package limiter

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
)

// Atomic fields are individually race-free, but expiring an old window must
// also be atomic with renewing it. An old expiry must never clear a new rate.
func TestDynamicExpiryDoesNotEraseRenewedLimit(t *testing.T) {
	l, tag := newLimiterWith(t, panel.UserInfo{Id: 1, Uuid: "u"})
	key := format.UserTag(tag, "u")
	v, _ := l.UserLimitInfo.Load(key)
	info := v.(*UserLimitInfo)
	oldExpiry := time.Now().Add(-time.Minute)
	newExpiry := time.Now().Add(time.Hour)
	stop := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = l.speedBucket(key)
				}
			}
		})
	}
	defer func() { close(stop); workers.Wait() }()
	for i := 0; i < 100_000; i++ {
		_ = l.UpdateDynamicSpeedLimit(tag, "u", 1, oldExpiry)
		runtime.Gosched()
		_ = l.UpdateDynamicSpeedLimit(tag, "u", 2, newExpiry)
		runtime.Gosched()
		if info.DynamicSpeedLimit.Load() == 0 && info.ExpireTime.Load() == newExpiry.Unix() {
			t.Fatalf("old expiry erased a renewed limit after %d renewals", i+1)
		}
	}
}
