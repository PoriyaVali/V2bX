package node

import (
	"errors"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

// preparingReloadCore is a reloadCore whose cores prepare nodes ahead of
// AddNode, as TrustTunnel does with its certificate.
type preparingReloadCore struct {
	reloadCore
	failPrepare int
	// events is the order of PrepareNode and DelNode calls.
	events []string
}

func (p *preparingReloadCore) PrepareNode(string, *panel.NodeInfo, *conf.Options) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, "prepare")
	if p.failPrepare > 0 {
		p.failPrepare--
		return errors.New("authority unreachable")
	}
	return nil
}

func (p *preparingReloadCore) DelNode(tag string) error {
	p.mu.Lock()
	p.events = append(p.events, "del")
	p.mu.Unlock()
	return p.reloadCore.DelNode(tag)
}

// 🔴 A reload must not retire a working node before its core has done what can
// fail. TrustTunnel issues the node's certificate in AddNode, which ran after
// the old endpoint was gone: a new hostname left the node down for the whole
// issuance, and for good when the authority did not answer.
func TestReload_PreparesBeforeRetiringAndKeepsTheOldNodeOnFailure(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &preparingReloadCore{}
	c := startedController(t, f, core, &conf.Options{})
	old := core.servedPort(c.tag)
	if old == 0 {
		t.Fatal("setup: the node did not start")
	}

	f.setPort(5555)
	core.mu.Lock()
	core.failPrepare = 1
	core.events = nil
	core.mu.Unlock()
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != old {
		t.Fatalf("a failed preparation retired the working node: core serves %d, want %d", got, old)
	}
	if p := c.reloadProblem.Load(); p == nil {
		t.Fatal("a failed preparation was not reported as the reload's problem")
	}

	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 5555 {
		t.Fatalf("the retry did not bring the node up on 5555; core serves %d", got)
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	want := []string{"prepare", "prepare", "del"}
	if len(core.events) != len(want) {
		t.Fatalf("events %v, want %v", core.events, want)
	}
	for i := range want {
		if core.events[i] != want[i] {
			t.Fatalf("events %v, want %v: preparation must come before the old node is retired", core.events, want)
		}
	}
	if p := c.reloadProblem.Load(); p != nil {
		t.Fatalf("the problem outlived the successful retry: %s", *p)
	}
}
