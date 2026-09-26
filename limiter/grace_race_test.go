package limiter

import (
	"fmt"
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
)

// The online report replaces the grace list while connections read it. The
// old code swapped a plain field under them (a data race under -race) and
// published an empty list before filling it. Run with -race.
func TestGetOnlineDevice_ConcurrentWithCheckLimit(t *testing.T) {
	Init()
	const tag = "grace-race"
	l := AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "u1", DeviceLimit: 50}}, map[int]int{1: 1})
	t.Cleanup(func() { DeleteLimiter(tag) })
	tu := format.UserTag(tag, "u1")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			l.CheckLimit(tu, fmt.Sprintf("10.0.0.%d", i%10), true, true)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_, _ = l.GetOnlineDevice()
		}
	}()
	wg.Wait()
}

// An address reported online last cycle is re-admitted from the grace list
// even when the user is at their limit by the panel's (lagging) count.
func TestGetOnlineDevice_ReportedAddressIsGraced(t *testing.T) {
	Init()
	const tag = "grace"
	l := AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 7, Uuid: "u7", DeviceLimit: 1}}, map[int]int{})
	t.Cleanup(func() { DeleteLimiter(tag) })
	tu := format.UserTag(tag, "u7")
	if _, reject := l.CheckLimit(tu, "5.5.5.5", true, true); reject {
		t.Fatal("first device rejected")
	}
	online, _ := l.GetOnlineDevice()
	if len(*online) != 1 || (*online)[0].IP != "5.5.5.5" {
		t.Fatalf("report = %+v", *online)
	}
	// The panel now counts one device - the limit - for this user.
	l.SetAliveList(map[int]int{7: 1})
	if _, reject := l.CheckLimit(tu, "5.5.5.5", true, true); reject {
		t.Fatal("the device that was just reported online was locked out")
	}
	if _, reject := l.CheckLimit(tu, "6.6.6.6", true, true); !reject {
		t.Fatal("a second device was admitted over a limit of 1")
	}
}
