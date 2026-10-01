package node

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
)

func TestReportDisablingThresholdFlushesSavedBytes(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u"}})
	core := &stubCore{}
	c := newSyncedController(t, f, core)
	info := *c.info
	info.NodeReportMinTraffic = 100
	c.setInfo(&info)
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 123, Download: 456}})
	_ = c.reportUserTrafficTask()
	if len(f.pushLog()) != 0 {
		t.Fatal("sub-threshold traffic was sent early")
	}
	info.NodeReportMinTraffic = 0
	c.setInfo(&info)
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 10, Download: 20}})
	_ = c.reportUserTrafficTask()
	pushes := f.pushLog()
	if len(pushes) != 1 || pushes[0].body[1][0] != 133 || pushes[0].body[1][1] != 476 {
		t.Fatalf("disabling the threshold lost accumulated traffic: %+v", pushes)
	}
	if len(c.reportAccum) != 0 {
		t.Fatal("flushed bytes remain in the accumulator")
	}
}

func TestCloseFlushesSubThresholdTraffic(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u"}})
	core := &stubCore{}
	c := newSyncedController(t, f, core)
	info := *c.info
	info.NodeReportMinTraffic = 100
	c.setInfo(&info)
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 12, Download: 34}})
	_ = c.reportUserTrafficTask()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	pushes := f.pushLog()
	if len(pushes) != 1 || pushes[0].body[1][0] != 12 || pushes[0].body[1][1] != 34 {
		t.Fatalf("shutdown lost sub-threshold bytes: %+v", pushes)
	}
}

type liveDeviceCore struct {
	stubCore
	online []panel.OnlineUser
	bytes  map[int]map[string]int64
	drains int
}

func (s *liveDeviceCore) OnlineDevices(string) ([]panel.OnlineUser, error) {
	return append([]panel.OnlineUser(nil), s.online...), nil
}

func (s *liveDeviceCore) GetDeviceTrafficSlice(_ string, reset bool) (map[int]map[string]int64, error) {
	out := s.bytes
	if out == nil {
		out = make(map[int]map[string]int64)
	}
	if reset {
		s.drains++
		s.bytes = nil
	}
	return out, nil
}

func TestReportDrainsAndDeduplicatesEstablishedDevicesEveryCycle(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u", DeviceLimit: 1}})
	core := &liveDeviceCore{
		online: []panel.OnlineUser{{UID: 1, IP: "::ffff:5.5.5.5"}},
		bytes:  map[int]map[string]int64{1: {"5.5.5.5": 100}},
	}
	c := newSyncedController(t, f, core)
	key := format.UserTag(c.tag, "u")
	if _, reject := c.limiter.CheckLimit(key, "5.5.5.5", true, true); reject {
		t.Fatal("first handshake refused")
	}
	for i := 0; i < 4; i++ {
		_ = c.reportUserTrafficTask()
		got := f.reportedOnline()[1]
		if len(got) != 1 || got[0] != "5.5.5.5" {
			t.Fatalf("cycle %d lost or duplicated an established device: %v", i, got)
		}
	}
	f.mu.Lock()
	reports := f.aliveReports
	f.mu.Unlock()
	if reports != 4 || core.drains != 4 {
		t.Fatalf("reports=%d drains=%d, want 4 even without fresh handshakes", reports, core.drains)
	}
	c.limiter.SetAliveList(map[int]int{1: 1})
	if _, reject := c.limiter.CheckLimit(key, "5.5.5.5", true, true); reject {
		t.Fatal("established device lost its grace slot after repeated reports")
	}
	core.online = nil
	_ = c.reportUserTrafficTask()
	if core.drains != 5 {
		t.Fatal("empty online snapshot skipped draining per-IP counters")
	}
}

func TestReportPerDeviceThresholdUsesCurrentCycleBytes(t *testing.T) {
	f := newFakePanel(t, 10, []panel.UserInfo{{Id: 1, Uuid: "u"}})
	core := &liveDeviceCore{
		online: []panel.OnlineUser{{UID: 1, IP: "5.5.5.5"}},
		bytes:  map[int]map[string]int64{1: {"5.5.5.5": 20_000}},
	}
	c := newSyncedController(t, f, core)
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 20_000}})
	_ = c.reportUserTrafficTask()
	if len(f.reportedOnline()[1]) != 1 {
		t.Fatal("busy device was filtered out")
	}
	// User traffic from another source must not make this now-idle IP count.
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 50_000}})
	_ = c.reportUserTrafficTask()
	if len(f.reportedOnline()[1]) != 0 {
		t.Fatal("empty per-device sample fell back to the user's aggregate traffic")
	}
}
