package node

import (
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/limiter"
)

// dynLimit reads back the DynamicSpeedLimit the limiter stored for a user.
func dynLimit(t *testing.T, lim *limiter.Limiter, tag, uuid string) int {
	t.Helper()
	v, ok := lim.UserLimitInfo.Load(format.UserTag(tag, uuid))
	if !ok {
		t.Fatalf("no UserLimitInfo for %s", uuid)
	}
	return v.(*limiter.UserLimitInfo).DynamicSpeedLimit
}

// TestSpeedCheckerThrottlesAndResets verifies the restored dynamic speed limit:
// users whose accumulated traffic crossed the threshold get throttled, users
// below it are untouched, an unknown UID is skipped without panicking, and the
// accumulator resets for the next window.
func TestSpeedCheckerThrottlesAndResets(t *testing.T) {
	limiter.Init()
	const tag = "dyn-test-node"
	users := []panel.UserInfo{
		{Id: 1, Uuid: "uuid-1"},
		{Id: 2, Uuid: "uuid-2"},
	}
	lim := limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)

	c := &Controller{
		tag:     tag,
		limiter: lim,
		traffic: map[int]int64{
			1: 2000, // over threshold -> throttle
			2: 500,  // under threshold -> leave alone
			3: 9999, // over threshold but no UID->UUID mapping -> must skip safely
		},
		uidToUUID: map[int]string{1: "uuid-1", 2: "uuid-2"},
		Options: &conf.Options{
			LimitConfig: conf.LimitConfig{
				EnableDynamicSpeedLimit: true,
				DynamicSpeedLimitConfig: &conf.DynamicSpeedLimitConfig{
					Periodic:   60,
					Traffic:    1000,
					SpeedLimit: 50,
					ExpireTime: 10,
				},
			},
		},
	}

	if err := c.SpeedChecker(); err != nil {
		t.Fatalf("SpeedChecker returned error: %v", err)
	}

	if got := dynLimit(t, lim, tag, "uuid-1"); got != 50 {
		t.Errorf("uuid-1 DynamicSpeedLimit = %d, want 50 (throttled)", got)
	}
	if got := dynLimit(t, lim, tag, "uuid-2"); got != 0 {
		t.Errorf("uuid-2 DynamicSpeedLimit = %d, want 0 (not throttled)", got)
	}

	c.trafficMu.Lock()
	n := len(c.traffic)
	c.trafficMu.Unlock()
	if n != 0 {
		t.Errorf("traffic accumulator not reset for next window, len = %d", n)
	}
}

// TestSpeedCheckerNoThreshold ensures nothing is throttled when every user is
// below the configured traffic threshold.
func TestSpeedCheckerNoThreshold(t *testing.T) {
	limiter.Init()
	const tag = "dyn-test-node-2"
	users := []panel.UserInfo{{Id: 1, Uuid: "u1"}}
	lim := limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)

	c := &Controller{
		tag:       tag,
		limiter:   lim,
		traffic:   map[int]int64{1: 100},
		uidToUUID: map[int]string{1: "u1"},
		Options: &conf.Options{
			LimitConfig: conf.LimitConfig{
				EnableDynamicSpeedLimit: true,
				DynamicSpeedLimitConfig: &conf.DynamicSpeedLimitConfig{
					Periodic: 60, Traffic: 1000, SpeedLimit: 50, ExpireTime: 10,
				},
			},
		},
	}
	if err := c.SpeedChecker(); err != nil {
		t.Fatalf("SpeedChecker returned error: %v", err)
	}
	if got := dynLimit(t, lim, tag, "u1"); got != 0 {
		t.Errorf("u1 DynamicSpeedLimit = %d, want 0", got)
	}
}

// TestSpeedCheckerConcurrent hammers the accumulator from a "report" goroutine
// while a "checker" goroutine runs SpeedChecker, plus node-change resets. This
// is the exact multi-goroutine access pattern the trafficMu guard exists for: a
// missing lock would trip Go's "concurrent map read and map write" fatal panic
// (which fires even without the race detector, so this is a real safety net).
func TestSpeedCheckerConcurrent(t *testing.T) {
	limiter.Init()
	const tag = "dyn-test-node-3"
	users := []panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}}
	lim := limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)

	c := &Controller{
		tag:       tag,
		limiter:   lim,
		traffic:   map[int]int64{},
		uidToUUID: map[int]string{1: "u1", 2: "u2"},
		Options: &conf.Options{
			LimitConfig: conf.LimitConfig{
				EnableDynamicSpeedLimit: true,
				DynamicSpeedLimitConfig: &conf.DynamicSpeedLimitConfig{
					Periodic: 1, Traffic: 1000, SpeedLimit: 50, ExpireTime: 10,
				},
			},
		},
	}

	const iters = 2000
	var wg sync.WaitGroup
	wg.Add(3)
	// reporter: accumulates like reportUserTrafficTask
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			c.trafficMu.Lock()
			if c.traffic == nil {
				c.traffic = make(map[int]int64)
			}
			c.traffic[1] += 300
			c.traffic[2] += 300
			c.trafficMu.Unlock()
		}
	}()
	// checker: runs SpeedChecker (ranges + resets under the lock)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = c.SpeedChecker()
		}
	}()
	// node-change resets (mirrors nodeInfoMonitor)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			c.trafficMu.Lock()
			c.traffic = make(map[int]int64)
			c.trafficMu.Unlock()
		}
	}()
	wg.Wait()
}
