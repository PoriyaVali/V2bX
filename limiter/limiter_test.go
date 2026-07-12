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
