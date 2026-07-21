package node

import (
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
)

// recordingCore captures what the controller asks the core to tear down, which
// is the only externally visible proof that a removal actually reached the
// inbound rather than stopping at the panel client.
type recordingCore struct {
	stubCore
	mu      sync.Mutex
	deleted []panel.UserInfo
}

func (r *recordingCore) DelUsers(users []panel.UserInfo, _ string, _ *panel.NodeInfo) error {
	r.mu.Lock()
	r.deleted = append(r.deleted, users...)
	r.mu.Unlock()
	return nil
}

func (r *recordingCore) deletedUUIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.deleted))
	for _, u := range r.deleted {
		out = append(out, u.Uuid)
	}
	return out
}

// An empty user list is an ANSWER - "nobody is authorised on this node any
// more" - and every user has to be torn out of the inbound.
//
// This is how a metered tier ends: the panel stops listing a user the moment
// their balance reaches zero. The node used to skip the whole membership
// comparison whenever the incoming list was empty, because an empty list was
// indistinguishable from the panel's 304 "nothing changed". The last user of a
// node therefore kept their connection - and kept using a tier they could no
// longer pay for - until the process happened to restart.
func TestPoll_PanelEmptyingTheListRemovesEveryone(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{
		{Id: 1, Uuid: "u1", SpeedLimit: 10, DeviceLimit: 2},
		{Id: 2, Uuid: "u2", SpeedLimit: 10, DeviceLimit: 2},
	})
	core := &recordingCore{}
	c := newSyncedController(t, f, core)

	if len(c.userList) != 2 {
		t.Fatalf("setup: userList = %d users, want 2", len(c.userList))
	}

	// The panel cuts everyone off - exactly what it serves today: 200 with
	// {"users":[]}, not a 304 and not an error.
	f.setUsers([]panel.UserInfo{})
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}

	if got := core.deletedUUIDs(); len(got) != 2 {
		t.Fatalf("panel returned an empty list but the core was asked to remove %v; "+
			"users cut off by the panel stay connected", got)
	}
	if len(c.userList) != 0 {
		t.Fatalf("userList still holds %d users after the panel emptied it", len(c.userList))
	}
}

// The complement, and the reason the empty case was special-cased in the first
// place: a 304 means "you already have the current list", so it must leave
// membership completely alone. Reading it as an empty list would tear every
// user off the node on the first unchanged poll - roughly once a minute.
func TestPoll_NotModifiedLeavesTheUserListAlone(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{
		{Id: 1, Uuid: "u1", SpeedLimit: 10, DeviceLimit: 2},
	})
	core := &recordingCore{}
	c := newSyncedController(t, f, core)

	f.enableEtag()
	// Prime the client's etag, then poll again with nothing changed so the fake
	// answers 304.
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}

	if got := core.deletedUUIDs(); len(got) != 0 {
		t.Fatalf("a 304 removed %v from the core; an unchanged list must not "+
			"disconnect anybody", got)
	}
	if len(c.userList) != 1 {
		t.Fatalf("userList = %d users after a 304, want the 1 it already held", len(c.userList))
	}
}
