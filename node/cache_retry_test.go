package node

import (
	"errors"
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
)

func TestPollConfigIsRetriedAfterUserFetchFailure(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := newSyncedController(t, f, core)
	f.setPort(5555)
	f.mu.Lock()
	f.userFails = true
	f.mu.Unlock()
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 1234 {
		t.Fatalf("failed poll changed the core's port to %d", got)
	}
	f.mu.Lock()
	f.userFails = false
	f.mu.Unlock()
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 5555 {
		t.Fatalf("cached config was lost after a user fetch failure: port %d", got)
	}
}

// A partial batch makes a plain retry unsafe: users already added reject a
// duplicate, while users already deleted are no longer present to remove.
type partialMembershipCore struct {
	stubCore
	mu          sync.Mutex
	members     map[string]int
	failAddUser bool
	failDelUser bool
	rebuilds    int
}

func (s *partialMembershipCore) AddNode(string, *panel.NodeInfo, *conf.Options) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.members = make(map[string]int)
	s.rebuilds++
	return nil
}

func (s *partialMembershipCore) DelNode(string) error {
	s.mu.Lock()
	s.members = nil
	s.mu.Unlock()
	return nil
}

func (s *partialMembershipCore) AddUsers(p *vCore.AddUsersParams) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range p.Users {
		if _, exists := s.members[u.Uuid]; exists {
			return i, errors.New("duplicate user")
		}
		s.members[u.Uuid] = u.Id
		if s.failAddUser {
			s.failAddUser = false
			return i + 1, errors.New("partially applied add")
		}
	}
	return len(p.Users), nil
}

func (s *partialMembershipCore) DelUsers(users []panel.UserInfo, _ string, _ *panel.NodeInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range users {
		if _, exists := s.members[u.Uuid]; !exists {
			return errors.New("user already absent")
		}
		delete(s.members, u.Uuid)
		if s.failDelUser {
			s.failDelUser = false
			return errors.New("partially applied delete")
		}
	}
	return nil
}

func TestPollRecoversPartialMembershipWithCachedPanelList(t *testing.T) {
	all := []panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}, {Id: 3, Uuid: "u3"}}
	for _, deleting := range []bool{false, true} {
		name := "add"
		initial, wanted := all[:1], all
		if deleting {
			name, initial, wanted = "delete", all, all[:1]
		}
		t.Run(name, func(t *testing.T) {
			f := newFakePanel(t, 0, initial)
			f.enableEtag()
			core := &partialMembershipCore{}
			c := newSyncedController(t, f, core)
			core.mu.Lock()
			core.failAddUser, core.failDelUser = !deleting, deleting
			core.mu.Unlock()
			f.setUsers(wanted)
			_ = c.nodeInfoMonitor()
			if !c.needsReload {
				t.Fatal("partial failure did not request a full rebuild")
			}
			// No further panel edit: the API would return 304 without invalidation.
			_ = c.nodeInfoMonitor()
			core.mu.Lock()
			defer core.mu.Unlock()
			if c.needsReload || core.rebuilds != 2 || len(core.members) != len(wanted) {
				t.Fatalf("recovery: reload=%v rebuilds=%d members=%v", c.needsReload, core.rebuilds, core.members)
			}
			for _, u := range wanted {
				if core.members[u.Uuid] != u.Id {
					t.Fatalf("user %s missing after recovery", u.Uuid)
				}
				if _, reject := c.limiter.CheckLimit(format.UserTag(c.tag, u.Uuid), "5.5.5.5", true, false); reject {
					t.Fatalf("recovered user %s absent from limiter", u.Uuid)
				}
			}
			if deleting {
				if _, reject := c.limiter.CheckLimit(format.UserTag(c.tag, "u2"), "5.5.5.5", true, false); !reject {
					t.Fatal("removed user survived in the limiter")
				}
			}
		})
	}
}
