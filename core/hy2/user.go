package hy2

import (
	"fmt"
	"net"
	"sync"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/counter"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/apernet/hysteria/core/v2/server"
)

var _ server.Authenticator = &V2bX{}

// V2bX authenticates the users of one node.
type V2bX struct {
	usersMap map[string]int // uuid -> panel UID
	mutex    sync.RWMutex
}

func (v *V2bX) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	if v.uid(auth) != 0 {
		return true, auth
	}
	return false, ""
}

// uid returns the user's panel id, or 0 for someone not on the node.
func (v *V2bX) uid(uuid string) int {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return v.usersMap[uuid]
}

func (h *Hysteria2) AddUsers(p *vCore.AddUsersParams) (added int, err error) {
	n := h.node(p.Tag)
	if n == nil {
		return 0, fmt.Errorf("hysteria2: node %s not found", p.Tag)
	}
	n.Auth.mutex.Lock()
	for _, u := range p.Users {
		n.Auth.usersMap[u.Uuid] = u.Id
	}
	n.Auth.mutex.Unlock()
	return len(p.Users), nil
}

func (h *Hysteria2) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	n := h.node(tag)
	if n == nil {
		return fmt.Errorf("hysteria2: node %s not found", tag)
	}
	hook := n.TrafficLogger.(*HookServer)
	n.Auth.mutex.Lock()
	for _, u := range users {
		delete(n.Auth.usersMap, u.Uuid)
	}
	n.Auth.mutex.Unlock()
	// After the user set, so a report racing this cannot recreate the entry.
	for _, u := range users {
		if v, ok := hook.Counter.Load(tag); ok {
			v.(*counter.TrafficCounter).Delete(u.Uuid)
		}
	}
	return nil
}

func (h *Hysteria2) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	n := h.node(tag)
	if n == nil {
		// Between a reload's DelNode and AddNode. The ledger is kept, so the
		// traffic goes out in the next report.
		return nil, nil
	}
	hook := n.TrafficLogger.(*HookServer)
	v, ok := hook.Counter.Load(tag)
	if !ok {
		return nil, nil
	}
	min := hook.reportMin.Load()
	var trafficSlice []panel.UserTraffic
	v.(*counter.TrafficCounter).Counters.Range(func(key, value interface{}) bool {
		uuid := key.(string)
		traffic := value.(*counter.TrafficStorage)
		if traffic.UpCounter.Load()+traffic.DownCounter.Load() <= min {
			return true
		}
		uid := n.Auth.uid(uuid)
		if uid == 0 {
			// Not (or not yet) on this node: right after a reload the users
			// are added a moment after the node. Leave the bytes for the next
			// report - resetting first, as this used to, lost them.
			return true
		}
		up, down := traffic.UpCounter.Load(), traffic.DownCounter.Load()
		if reset {
			// Swap, not Store(0): bytes counted between the Load above and a
			// plain reset were wiped without ever being reported.
			up = traffic.UpCounter.Swap(0)
			down = traffic.DownCounter.Swap(0)
		}
		trafficSlice = append(trafficSlice, panel.UserTraffic{
			UID:      uid,
			Upload:   up,
			Download: down,
		})
		return true
	})
	return trafficSlice, nil
}
