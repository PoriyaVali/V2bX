package node

import (
	"errors"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
)

type retiringCore struct {
	stubCore
	retired    []panel.UserTraffic
	calls      int
	unreadable bool
}

func (r *retiringCore) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	if r.unreadable {
		return nil, errors.New("replacement node is unavailable")
	}
	return r.stubCore.GetUserTrafficSlice(tag, reset)
}

func (r *retiringCore) RetireNode(string) ([]panel.UserTraffic, error) {
	r.calls++
	result := r.retired
	r.retired = nil
	return result, nil
}

func TestCloseCollectsTrafficAfterCompletedRetirement(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 7, Uuid: "old"}})
	core := &retiringCore{retired: []panel.UserTraffic{{UID: 7, Upload: 3, Download: 4}}}
	c := newSyncedController(t, f, core)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	pushes := f.pushLog()
	if core.calls != 1 || len(pushes) != 1 || pushes[0].body[7][0] != 3 || pushes[0].body[7][1] != 4 {
		t.Fatalf("post-close bytes were lost: retire calls=%d reports=%+v", core.calls, pushes)
	}
}

func TestReloadRetiredTrafficIsReportedEvenWhileNodeDown(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 7, Uuid: "old"}})
	core := &retiringCore{retired: []panel.UserTraffic{{UID: 7, Upload: 3, Download: 4}}}
	c := newSyncedController(t, f, core)
	f.setPort(5555)
	f.setUsers([]panel.UserInfo{{Id: 9, Uuid: "new"}})
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	core.unreadable = true
	if err := c.reportUserTrafficTask(); err != nil {
		t.Fatal(err)
	}
	pushes := f.pushLog()
	if core.calls != 1 || len(pushes) != 1 || pushes[0].body[7][0] != 3 || pushes[0].body[7][1] != 4 {
		t.Fatalf("old UID's retired bytes were lost or reassigned: retire calls=%d reports=%+v", core.calls, pushes)
	}
}
