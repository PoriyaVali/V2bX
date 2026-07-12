package limiter

import (
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
)

func newTestLimiter(deviceLimit, alive int) (*Limiter, string) {
	Init()
	tag := "test-node"
	users := []panel.UserInfo{{Id: 1, Uuid: "u1", DeviceLimit: deviceLimit}}
	l := AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{1: alive})
	return l, format.UserTag(tag, "u1")
}

func onlineIPCount(l *Limiter, taguuid string) int {
	v, ok := l.UserOnlineIP.Load(taguuid)
	if !ok {
		return 0
	}
	n := 0
	v.(*sync.Map).Range(func(_, _ any) bool { n++; return true })
	return n
}

func TestCheckLimit_UnknownUser_Rejected(t *testing.T) {
	l, _ := newTestLimiter(2, 0)
	if _, reject := l.CheckLimit("does-not-exist", "1.1.1.1", true, true); !reject {
		t.Fatal("unknown user must be rejected")
	}
}

func TestCheckLimit_UnderLimit_Allowed_AndRegistered(t *testing.T) {
	l, tag := newTestLimiter(2, 1) // alive 1 < limit 2
	if _, reject := l.CheckLimit(tag, "1.1.1.1", true, true); reject {
		t.Fatal("under device limit must be allowed")
	}
	if onlineIPCount(l, tag) != 1 {
		t.Fatalf("expected ip registered as online, got %d", onlineIPCount(l, tag))
	}
}

func TestCheckLimit_AtLimit_NewIP_Rejected(t *testing.T) {
	l, tag := newTestLimiter(2, 2) // alive 2 == limit 2
	if _, reject := l.CheckLimit(tag, "9.9.9.9", true, true); !reject {
		t.Fatal("new ip at device limit must be rejected")
	}
}

func TestCheckLimit_ExistingIP_AllowedEvenOverLimit(t *testing.T) {
	l, tag := newTestLimiter(2, 1)
	if _, reject := l.CheckLimit(tag, "1.1.1.1", true, true); reject {
		t.Fatal("first ip must be allowed")
	}
	l.SetAliveList(map[int]int{1: 5}) // now way over limit
	if _, reject := l.CheckLimit(tag, "1.1.1.1", true, true); reject {
		t.Fatal("already-counted ip must not be rejected even over limit")
	}
	if _, reject := l.CheckLimit(tag, "2.2.2.2", true, true); !reject {
		t.Fatal("a NEW ip over limit must be rejected")
	}
}

func TestCheckLimit_NoSSUDPFalse_SkipsDeviceCheck(t *testing.T) {
	l, tag := newTestLimiter(2, 5) // over limit
	if _, reject := l.CheckLimit(tag, "3.3.3.3", true, false); reject {
		t.Fatal("noSSUDP=false must skip the device-limit check")
	}
}

func TestGetOnlineDevice_ReturnsRegisteredIPs(t *testing.T) {
	l, tag := newTestLimiter(3, 0)
	l.CheckLimit(tag, "1.1.1.1", true, true)
	l.CheckLimit(tag, "2.2.2.2", true, true)
	online, err := l.GetOnlineDevice()
	if err != nil {
		t.Fatal(err)
	}
	if len(*online) != 2 {
		t.Fatalf("expected 2 online devices, got %d", len(*online))
	}
}

// TestCheckLimit_RejectedFirstConnection_LeavesNoOnlineEntry is the core of the
// self-heal fix: when a user is at/over their device limit with no locally
// registered IP yet (e.g. right after a restart, while the panel's alive count
// is still stale), the rejected connection must NOT leave a transient online-IP
// entry. Otherwise the periodic report keeps re-reporting the locked-out user,
// pinning the panel's alive count and deadlocking a legitimate single device.
func TestCheckLimit_RejectedFirstConnection_LeavesNoOnlineEntry(t *testing.T) {
	l, tag := newTestLimiter(1, 1) // limit 1, alive already 1 (stale after restart)
	if _, reject := l.CheckLimit(tag, "5.5.5.5", true, true); !reject {
		t.Fatal("first ip at device limit must be rejected")
	}
	if n := onlineIPCount(l, tag); n != 0 {
		t.Fatalf("rejected connection must leave no online-IP entry, got %d", n)
	}
	online, _ := l.GetOnlineDevice()
	if len(*online) != 0 {
		t.Fatalf("locked-out user must not be reported online, got %d", len(*online))
	}
}

// TestCheckLimit_SelfHealsWhenAliveDrops verifies recovery: a single device that
// was wrongly locked out (stale alive=1) is admitted again as soon as the panel's
// alive count decays to 0 — no manual cache clearing needed.
func TestCheckLimit_SelfHealsWhenAliveDrops(t *testing.T) {
	l, tag := newTestLimiter(1, 1)
	if _, reject := l.CheckLimit(tag, "5.5.5.5", true, true); !reject {
		t.Fatal("must be rejected while alive is stale-high")
	}
	l.SetAliveList(map[int]int{1: 0}) // panel count decayed
	if _, reject := l.CheckLimit(tag, "5.5.5.5", true, true); reject {
		t.Fatal("single device must be admitted once alive drops to 0")
	}
	if n := onlineIPCount(l, tag); n != 1 {
		t.Fatalf("admitted ip must be registered, got %d", n)
	}
}

// TestCheckLimit_RejectedSecondIP_KeepsFirst ensures rejecting a genuine second
// device does not disturb the first device's registration.
func TestCheckLimit_RejectedSecondIP_KeepsFirst(t *testing.T) {
	l, tag := newTestLimiter(1, 0)
	if _, reject := l.CheckLimit(tag, "1.1.1.1", true, true); reject {
		t.Fatal("first device must be admitted")
	}
	l.SetAliveList(map[int]int{1: 1}) // panel now counts the first device
	if _, reject := l.CheckLimit(tag, "2.2.2.2", true, true); !reject {
		t.Fatal("second device over limit must be rejected")
	}
	if n := onlineIPCount(l, tag); n != 1 {
		t.Fatalf("first device must stay registered and the rejected ip must not be added, got %d", n)
	}
}

// BenchmarkCheckLimit_ReturningUser exercises the hot path where the user's
// online-IP map already exists (the common case) — this is what the allocation
// optimization targets.
func BenchmarkCheckLimit_ReturningUser(b *testing.B) {
	l, tag := newTestLimiter(100, 1)
	l.CheckLimit(tag, "1.1.1.1", true, true) // pre-register
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.CheckLimit(tag, "1.1.1.1", true, true)
	}
}
