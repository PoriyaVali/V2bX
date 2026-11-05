package node

import (
	"errors"
	"reflect"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
)

// preparingReloadCore is a reloadCore whose cores prepare nodes ahead of
// AddNode, as TrustTunnel does with its certificate.
type preparingReloadCore struct {
	reloadCore
	failPrepare  int
	failDelUsers int
	// events is the order of PrepareNode and DelNode calls.
	events []string
	// What each DelUsers and AddUsers call gave the core.
	removed, joined [][]string
}

func uuids(users []panel.UserInfo) []string {
	out := make([]string, len(users))
	for i, u := range users {
		out[i] = u.Uuid
	}
	return out
}

func (p *preparingReloadCore) DelUsers(users []panel.UserInfo, _ string, _ *panel.NodeInfo) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failDelUsers > 0 {
		p.failDelUsers--
		return errors.New("credentials not written")
	}
	p.removed = append(p.removed, uuids(users))
	return nil
}

func (p *preparingReloadCore) AddUsers(params *vCore.AddUsersParams) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.joined = append(p.joined, uuids(params.Users))
	return len(params.Users), nil
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

// 🔴 When a reload stops and keeps the old node, a user the panel removed in
// the same poll must be cut off there too. Only the limiter was updated, which
// TrustTunnel's endpoint never consults: it authenticates from its own
// credentials, so the removed user kept connecting for as long as preparation
// kept failing, and no later poll had anyone left to remove.
func TestReload_KeptNodeDropsRemovedUsersAndAddsNewOnes(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}})
	core := &preparingReloadCore{}
	c := startedController(t, f, core, &conf.Options{})
	old := core.servedPort(c.tag)

	f.setPort(5555)
	f.setUsers([]panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 3, Uuid: "u3"}})
	core.mu.Lock()
	core.failPrepare, core.removed, core.joined = 1, nil, nil
	core.mu.Unlock()
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != old {
		t.Fatalf("setup: the failed preparation was meant to keep the old node; core serves %d", got)
	}
	core.mu.Lock()
	removed, joined := core.removed, core.joined
	core.mu.Unlock()
	if !reflect.DeepEqual(removed, [][]string{{"u2"}}) {
		t.Fatalf("the kept node was not told u2 is gone: %v", removed)
	}
	if !reflect.DeepEqual(joined, [][]string{{"u3"}}) {
		t.Fatalf("the kept node was not given u3: %v", joined)
	}

	// The retried reload rebuilds the node with exactly the panel's members.
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 5555 {
		t.Fatalf("the retry did not bring the node up on 5555; core serves %d", got)
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	if last := core.joined[len(core.joined)-1]; !reflect.DeepEqual(last, []string{"u1", "u3"}) {
		t.Fatalf("the rebuilt node got %v, want u1 and u3", last)
	}
}

// A kept node that cannot drop its removed users is stopped rather than left
// serving them; the retried reload brings it back.
func TestReload_KeptNodeThatCannotDropUsersIsStopped(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}})
	core := &preparingReloadCore{}
	c := startedController(t, f, core, &conf.Options{})

	f.setPort(5555)
	f.setUsers([]panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core.mu.Lock()
	core.failPrepare, core.failDelUsers = 1, 1
	core.mu.Unlock()
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 0 {
		t.Fatalf("a node still admitting a removed user kept serving on %d", got)
	}
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 5555 {
		t.Fatalf("the retry did not bring the node back on 5555; core serves %d", got)
	}
}
