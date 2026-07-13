package limiter

import (
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
)

func mbpsToBytes(mbps int64) int64 { return mbps * 1000000 / 8 }

func newLimiterWith(t *testing.T, users ...panel.UserInfo) (*Limiter, string) {
	t.Helper()
	Init()
	const tag = "limits-test"
	l := AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	t.Cleanup(func() { DeleteLimiter(tag) })
	return l, tag
}

// A device_limit raised in the panel must take effect on the next poll. It used
// to be invisible to the limiter entirely: compareUserList keyed users on
// uuid+speed_limit, so a device-limit-only change looked like "nothing changed"
// and an admin raising a locked-out user's limit to rescue them did nothing at
// all until the node was reloaded.
func TestUpdateUserLimits_DeviceLimitChangeTakesEffect(t *testing.T) {
	l, tag := newLimiterWith(t, panel.UserInfo{Id: 1, Uuid: "u1", DeviceLimit: 1})
	tu := format.UserTag(tag, "u1")
	l.SetAliveList(map[int]int{1: 1}) // already at the limit

	if _, reject := l.CheckLimit(tu, "1.1.1.1", true, true); !reject {
		t.Fatal("setup: a new device at device_limit=1 must be rejected")
	}

	// Admin raises the limit to 3 in the panel; the node polls it.
	l.UpdateUserLimits(tag, []panel.UserInfo{{Id: 1, Uuid: "u1", DeviceLimit: 3}})

	if _, reject := l.CheckLimit(tu, "1.1.1.1", true, true); reject {
		t.Fatal("device_limit raised to 3 (alive=1) but the limiter still rejects — change did not propagate")
	}
}

func TestUpdateUserLimits_LowerDeviceLimitAlsoTakesEffect(t *testing.T) {
	l, tag := newLimiterWith(t, panel.UserInfo{Id: 1, Uuid: "u1", DeviceLimit: 5})
	tu := format.UserTag(tag, "u1")
	l.SetAliveList(map[int]int{1: 2})

	if _, reject := l.CheckLimit(tu, "1.1.1.1", true, true); reject {
		t.Fatal("setup: under limit must be admitted")
	}
	l.UpdateUserLimits(tag, []panel.UserInfo{{Id: 1, Uuid: "u1", DeviceLimit: 2}}) // now at the limit

	if _, reject := l.CheckLimit(tu, "9.9.9.9", true, true); !reject {
		t.Fatal("device_limit lowered to 2 (alive=2) but a new device was still admitted")
	}
}

// A speed_limit change must rebuild the token bucket. The bucket is cached per
// user and never keyed by rate, so without an explicit drop the user keeps being
// served at the old rate forever.
func TestUpdateUserLimits_SpeedChangeRebuildsBucket(t *testing.T) {
	l, tag := newLimiterWith(t, panel.UserInfo{Id: 1, Uuid: "u1", SpeedLimit: 100})
	tu := format.UserTag(tag, "u1")

	b, _ := l.CheckLimit(tu, "1.1.1.1", true, true)
	if b == nil || b.Capacity() != mbpsToBytes(100) {
		t.Fatalf("setup: bucket = %v, want %d B/s", b, mbpsToBytes(100))
	}

	l.UpdateUserLimits(tag, []panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 10}})

	b, _ = l.CheckLimit(tu, "1.1.1.1", true, true)
	if b == nil || b.Capacity() != mbpsToBytes(10) {
		t.Fatalf("speed_limit 100→10 but bucket still serves %v B/s — stale bucket", b.Capacity())
	}
}

// Regression: a user whose personal speed_limit is 0 (i.e. unlimited — the
// common case) used to be deleted from UserLimitInfo the moment their dynamic
// speed limit expired. Their next connection then fell into the unknown-user
// branch of CheckLimit and was rejected — a permanent ban, until the node was
// restarted.
func TestDynamicSpeedLimit_ExpiryDoesNotBanUser(t *testing.T) {
	l, tag := newLimiterWith(t, panel.UserInfo{Id: 1, Uuid: "u1", SpeedLimit: 0})
	tu := format.UserTag(tag, "u1")

	if err := l.UpdateDynamicSpeedLimit(tag, "u1", 10, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, reject := l.CheckLimit(tu, "1.1.1.1", true, true); reject {
			t.Fatalf("connection %d rejected after the dynamic speed limit expired — user is permanently banned", i+1)
		}
	}
	if _, ok := l.UserLimitInfo.Load(tu); !ok {
		t.Fatal("UserLimitInfo was deleted on expiry — the next connection would be rejected as an unknown user")
	}
}

// The dynamic limit must actually throttle (even for a user who already has a
// bucket) and must actually lift when the window closes.
func TestDynamicSpeedLimit_AppliesThenLifts(t *testing.T) {
	l, tag := newLimiterWith(t, panel.UserInfo{Id: 1, Uuid: "u1", SpeedLimit: 100})
	tu := format.UserTag(tag, "u1")

	b, _ := l.CheckLimit(tu, "1.1.1.1", true, true) // caches a 100 Mbit bucket
	if b.Capacity() != mbpsToBytes(100) {
		t.Fatalf("setup: %d", b.Capacity())
	}

	// Throttle to 1 Mbit for the next 10 minutes.
	if err := l.UpdateDynamicSpeedLimit(tag, "u1", 1, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	b, _ = l.CheckLimit(tu, "1.1.1.1", true, true)
	if b.Capacity() != mbpsToBytes(1) {
		t.Fatalf("dynamic limit ignored: bucket still at %d B/s, want %d", b.Capacity(), mbpsToBytes(1))
	}

	// Window closes → back to the user's own 100 Mbit.
	if err := l.UpdateDynamicSpeedLimit(tag, "u1", 1, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	b, _ = l.CheckLimit(tu, "1.1.1.1", true, true)
	if b.Capacity() != mbpsToBytes(100) {
		t.Fatalf("throttle never lifted: bucket at %d B/s, want %d", b.Capacity(), mbpsToBytes(100))
	}
}

// The grace list is keyed by IP alone. Matching it back to the uid is what stops
// user B being admitted over their device limit just because user A was recently
// online from the same public address — routine behind CGNAT.
func TestGraceList_IsBoundToUid(t *testing.T) {
	l, tag := newLimiterWith(t,
		panel.UserInfo{Id: 1, Uuid: "a", DeviceLimit: 1},
		panel.UserInfo{Id: 2, Uuid: "b", DeviceLimit: 1},
	)
	l.SetAliveList(map[int]int{1: 0, 2: 5}) // b is far over their limit

	const sharedIP = "5.5.5.5"
	l.CheckLimit(format.UserTag(tag, "a"), sharedIP, true, true)
	_, _ = l.GetOnlineDevice() // moves a's IP into the grace list

	if _, reject := l.CheckLimit(format.UserTag(tag, "b"), sharedIP, true, true); !reject {
		t.Fatal("user b was admitted over their device limit via user a's grace-listed IP")
	}
	// a themselves must still be let back in — that is what the grace list is for.
	if _, reject := l.CheckLimit(format.UserTag(tag, "a"), sharedIP, true, true); reject {
		t.Fatal("user a was not re-admitted from their own grace-listed IP")
	}
}

// UserLimitInfo lives behind a sync.Map, which guards the map and not the struct
// it points at. CheckLimit reads/writes its fields on every connection while the
// speed checker writes them from another goroutine; with plain fields this is a
// data race (the detector flags ExpireTime and DynamicSpeedLimit). Run with -race.
func TestUserLimitInfo_ConcurrentAccessIsRaceFree(t *testing.T) {
	l, tag := newLimiterWith(t, panel.UserInfo{Id: 1, Uuid: "u1", SpeedLimit: 100, DeviceLimit: 5})
	tu := format.UserTag(tag, "u1")
	l.SetAliveList(map[int]int{1: 0})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // connection goroutines
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1500; j++ {
				l.CheckLimit(tu, "1.1.1.1", true, true)
			}
		}()
	}
	wg.Add(1) // speed checker
	go func() {
		defer wg.Done()
		for j := 0; j < 1500; j++ {
			_ = l.UpdateDynamicSpeedLimit(tag, "u1", 1, time.Now().Add(-time.Second))
		}
	}()
	wg.Add(1) // panel poll syncing limits
	go func() {
		defer wg.Done()
		for j := 0; j < 1500; j++ {
			l.UpdateUserLimits(tag, []panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 50, DeviceLimit: 3}})
		}
	}()
	wg.Wait()
}
