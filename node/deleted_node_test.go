package node

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// countingCore records the nodes the controller puts into it and takes out.
type countingCore struct {
	stubCore
	countMu        sync.Mutex
	added, removed int
}

func (c *countingCore) AddNode(string, *panel.NodeInfo, *conf.Options) error {
	c.countMu.Lock()
	c.added++
	c.countMu.Unlock()
	return nil
}

func (c *countingCore) DelNode(string) error {
	c.countMu.Lock()
	c.removed++
	c.countMu.Unlock()
	return nil
}

func (c *countingCore) counts() (int, int) {
	c.countMu.Lock()
	defer c.countMu.Unlock()
	return c.added, c.removed
}

// A node the panel deleted stops serving at once, says so once, and stops
// reporting; it serves again when the panel has it again.
func TestDeletedNodeStopsServingAndComesBack(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &countingCore{}
	c := newSyncedController(t, f, core)
	if added, _ := core.counts(); added != 1 || !c.nodeUp {
		t.Fatalf("node not up before the test: added %d, up %v", added, c.nodeUp)
	}

	hook := test.NewGlobal()
	defer hook.Reset()
	f.setDeleted(true)
	for i := 0; i < 3; i++ {
		_ = c.nodeInfoMonitor()
	}
	if _, removed := core.counts(); removed != 1 || c.nodeUp || !c.removed.Load() {
		t.Fatalf("deleted node still served: removed %d, up %v", removed, c.nodeUp)
	}
	warnings, errs := 0, 0
	for _, e := range hook.AllEntries() {
		switch e.Level {
		case log.WarnLevel:
			warnings++
		case log.ErrorLevel:
			errs++
		}
	}
	if warnings != 1 || errs != 0 {
		t.Fatalf("three polls of a deleted node logged %d warnings and %d errors, want one warning", warnings, errs)
	}

	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 5, Download: 6}})
	_ = c.reportUserTrafficTask()
	_ = c.reportNodeStatusTask()
	if len(f.pushLog())+len(f.idlePushes()) != 0 {
		t.Fatal("a deleted node kept reporting")
	}

	core.setTraffic(nil)
	f.setDeleted(false)
	_ = c.nodeInfoMonitor()
	if added, _ := core.counts(); added != 2 || !c.nodeUp || c.removed.Load() {
		t.Fatalf("restored node not served again: added %d, up %v", added, c.nodeUp)
	}
	_ = c.reportUserTrafficTask()
	if len(f.idlePushes()) != 1 {
		t.Fatal("restored node does not report")
	}
}

// A reload whose listener cannot bind leaves the node registered but not
// serving; its health says so, with the reason.
func TestHealthOfANodeThatCannotBind(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &failingUsersCore{}
	c := newSyncedController(t, f, core)
	if h := c.health(); !h.Serving || h.Users != 1 || h.Error != "" {
		t.Fatalf("healthy node reported %+v", h)
	}
	core.fail.Store(true)
	f.setPort(4321) // a config change: the node is rebuilt
	_ = c.nodeInfoMonitor()
	if h := c.health(); h.Serving || !strings.Contains(h.Error, "address already in use") {
		t.Fatalf("node that cannot bind reported %+v", h)
	}
	core.fail.Store(false)
	_ = c.nodeInfoMonitor()
	if h := c.health(); !h.Serving || h.Error != "" {
		t.Fatalf("recovered node reported %+v", h)
	}
}

// failingUsersCore refuses users, as a core whose listener cannot bind does.
type failingUsersCore struct {
	stubCore
	fail atomic.Bool
}

func (c *failingUsersCore) AddUsers(p *vCore.AddUsersParams) (int, error) {
	if c.fail.Load() {
		return 0, errors.New("listen tcp 0.0.0.0:4321: bind: address already in use")
	}
	return len(p.Users), nil
}

// stuckCore fails to take its node out as many times as failures says.
type stuckCore struct {
	countingCore
	failures atomic.Int32
}

func (c *stuckCore) DelNode(tag string) error {
	if c.failures.Add(-1) >= 0 {
		return errors.New("close listener: device or resource busy")
	}
	return c.countingCore.DelNode(tag)
}

// A deleted node the core failed to stop is stopped on a later poll, not
// left serving unmetered while the panel lacks it.
func TestDeletedNodeThatFailedToStopIsRetried(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &stuckCore{}
	c := newSyncedController(t, f, core)
	core.failures.Store(1)
	f.setDeleted(true)
	_ = c.nodeInfoMonitor()
	if _, removed := core.counts(); removed != 0 || !c.nodeUp {
		t.Fatalf("the stop did not fail as set up: removed %d, up %v", removed, c.nodeUp)
	}
	_ = c.nodeInfoMonitor()
	if _, removed := core.counts(); removed != 1 || c.nodeUp {
		t.Fatalf("deleted node still in the core after the next poll: removed %d, up %v", removed, c.nodeUp)
	}
}

// The panel may have the node again before the report task runs. What the
// deleted node served is dropped all the same, not billed to the node that
// came back.
func TestQuicklyRestoredNodeDoesNotReportTheDeletedNodesTraffic(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &countingCore{}
	c := newSyncedController(t, f, core)
	core.setTraffic([]panel.UserTraffic{{UID: 1, Upload: 5, Download: 6}})
	f.setDeleted(true)
	_ = c.nodeInfoMonitor() // the stop collects those bytes
	core.setTraffic(nil)
	f.setDeleted(false)
	_ = c.nodeInfoMonitor()
	if !c.nodeUp || c.removed.Load() {
		t.Fatalf("restored node not served again: up %v", c.nodeUp)
	}
	_ = c.reportUserTrafficTask()
	if pushed := f.pushLog(); len(pushed) != 0 {
		t.Fatalf("the restored node reported the deleted node's traffic: %+v", pushed[0].body)
	}
	if len(f.idlePushes()) != 1 {
		t.Fatal("restored node does not report")
	}
}
