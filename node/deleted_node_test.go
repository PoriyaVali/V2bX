package node

import (
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
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
