package node

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
)

func (f *fakePanel) pushLog() []pushAttempt {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]pushAttempt(nil), f.pushes...)
}

// A traffic batch the panel did not accept is resent on the next cycle under
// the SAME id, ahead of the new batch. The core's counters were reset when the
// batch was read, so it used to be lost outright; the id is what lets the
// panel count a resend once.
func TestReport_FailedBatchIsResentWithTheSameID(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &stubCore{}
	c := newSyncedController(t, f, core)

	f.mu.Lock()
	f.pushFails = 100 // every attempt of the first cycle fails, retries included
	f.mu.Unlock()
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 100, Download: 200}})
	_ = c.reportUserTrafficTask()
	if len(c.pendingReports) != 1 {
		t.Fatalf("failed batch not kept: %d pending", len(c.pendingReports))
	}
	firstID := c.pendingReports[0].id

	f.mu.Lock()
	f.pushFails = 0
	f.mu.Unlock()
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 5, Download: 7}})
	_ = c.reportUserTrafficTask()
	if len(c.pendingReports) != 0 {
		t.Fatalf("%d batch(es) still pending after the panel recovered", len(c.pendingReports))
	}

	var accepted []pushAttempt
	for _, p := range f.pushLog() {
		if p.id == "" {
			t.Fatal("a traffic report went out without an id")
		}
		if p.status == http.StatusOK {
			accepted = append(accepted, p)
		} else if p.id != firstID {
			t.Fatalf("a retry of the first batch changed its id: %s != %s", p.id, firstID)
		}
	}
	if len(accepted) != 2 {
		t.Fatalf("panel accepted %d batches, want 2", len(accepted))
	}
	if accepted[0].id != firstID || accepted[0].body[1][0] != 100 || accepted[0].body[1][1] != 200 {
		t.Fatalf("first accepted batch = %+v, want the resent one (id %s, 100/200)", accepted[0], firstID)
	}
	if accepted[1].id == firstID || accepted[1].body[1][0] != 5 {
		t.Fatalf("second accepted batch = %+v, want the new one", accepted[1])
	}
}

// The queue is bounded: a long outage drops the oldest batches, not memory.
func TestReport_QueueIsBounded(t *testing.T) {
	c := &Controller{}
	for i := 0; i < maxPendingReports+5; i++ {
		c.queueTrafficReport([]panel.UserTraffic{{UID: 1, Upload: int64(i)}})
	}
	if len(c.pendingReports) != maxPendingReports {
		t.Fatalf("queue holds %d, want %d", len(c.pendingReports), maxPendingReports)
	}
	if c.pendingReports[0].traffic[0].Upload != 5 {
		t.Fatalf("oldest kept batch is #%d, want #5", c.pendingReports[0].traffic[0].Upload)
	}
}

// unreadableCore answers like the Selector for a node it does not hold: between
// a reload's DelNode and AddNode, or after a reload failed in between.
type unreadableCore struct {
	stubCore
	unreadable atomic.Bool
}

func (u *unreadableCore) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	if u.unreadable.Load() {
		return nil, errors.New("the node is not have")
	}
	return u.stubCore.GetUserTrafficSlice(tag, reset)
}

// A cycle that cannot read the core still resends what earlier cycles could
// not send. Those batches no longer depend on the core, and holding them back
// until the node was up again kept billed traffic in memory only.
func TestReport_QueuedBatchIsResentWhenTheCoreCannotBeRead(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &unreadableCore{}
	c := newSyncedController(t, f, core)

	f.mu.Lock()
	f.pushFails = 100
	f.mu.Unlock()
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 100, Download: 200}})
	_ = c.reportUserTrafficTask()
	if len(c.pendingReports) != 1 {
		t.Fatalf("failed batch not kept: %d pending", len(c.pendingReports))
	}

	f.mu.Lock()
	f.pushFails = 0
	f.mu.Unlock()
	core.unreadable.Store(true)
	_ = c.reportUserTrafficTask()
	if len(c.pendingReports) != 0 {
		t.Fatalf("%d batch(es) still pending: the resend waited for the core", len(c.pendingReports))
	}
}

// A failed alive-list poll must not stop the user-list sync that follows it.
func TestPoll_AliveListFailureDoesNotBlockUserSync(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &stubCore{}
	c := newSyncedController(t, f, core)
	f.mu.Lock()
	f.aliveFails = true
	f.mu.Unlock()
	f.setUsers([]panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}})
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if len(c.userList) != 2 {
		t.Fatalf("user list not synced after an alive-list failure: %d users", len(c.userList))
	}
}
