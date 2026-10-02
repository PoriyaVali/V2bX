package limiter

import (
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
)

func TestSharedNATPreservesBothUsersGrace(t *testing.T) {
	users := []panel.UserInfo{
		{Id: 1, Uuid: "a", DeviceLimit: 1},
		{Id: 2, Uuid: "b", DeviceLimit: 1},
	}
	l, tag := newLimiterWith(t, users...)
	for _, u := range users {
		if _, reject := l.CheckLimit(format.UserTag(tag, u.Uuid), "5.5.5.5", true, true); reject {
			t.Fatal("initial connection refused")
		}
	}
	online, _ := l.GetOnlineDevice()
	if len(*online) != 2 {
		t.Fatalf("shared IP produced %d users, want 2", len(*online))
	}
	l.SetAliveList(map[int]int{1: 1, 2: 1})
	for _, u := range users {
		key := format.UserTag(tag, u.Uuid)
		if _, reject := l.CheckLimit(key, "5.5.5.5", true, true); reject {
			t.Fatalf("user %d lost their returning-device slot to another user", u.Id)
		}
		if _, reject := l.CheckLimit(key, "6.6.6.6", true, true); !reject {
			t.Fatalf("user %d admitted a different device over the limit", u.Id)
		}
	}
}

func TestLiveRateLimiterTracksPlanAndDynamicExpiry(t *testing.T) {
	l, tag := newLimiterWith(t, panel.UserInfo{Id: 1, Uuid: "u"})
	key := format.UserTag(tag, "u")
	live := l.RateLimiter(key) // established while unlimited
	l.UpdateUserLimits(tag, []panel.UserInfo{{Id: 1, Uuid: "u", SpeedLimit: 1}})
	bucket, reject := l.CheckLimit(key, "1.1.1.1", true, false)
	if reject || bucket == nil {
		t.Fatal("plan update did not create a bucket")
	}
	before := bucket.Available()
	live.Wait(10_000)
	if used := before - bucket.Available(); used <= 0 {
		t.Fatalf("existing limiter ignored the new plan: used %d tokens", used)
	}
	l.UpdateUserLimits(tag, []panel.UserInfo{{Id: 1, Uuid: "u"}})
	if err := l.UpdateDynamicSpeedLimit(tag, "u", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { live.Wait(100_000_000); close(done) }()
	select {
	case <-done:
		t.Fatal("dynamic limit did not throttle the existing connection")
	case <-time.After(30 * time.Millisecond):
	}
	if err := l.UpdateDynamicSpeedLimit(tag, "u", 1, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expired dynamic limit left an existing transfer throttled")
	}
}
