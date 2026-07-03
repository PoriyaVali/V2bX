package mdns

import (
	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
)

func (m *Mdns) AddUsers(p *vCore.AddUsersParams) (added int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[p.Tag]
	for _, u := range p.Users {
		m.usersMap[u.Uuid] = u.Id
		if n != nil {
			n.server.AddUser(u.Uuid)
		}
	}
	return len(p.Users), nil
}

func (m *Mdns) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[tag]
	for _, u := range users {
		delete(m.usersMap, u.Uuid)
		if n != nil {
			n.server.DelUser(u.Uuid)
		}
	}
	return nil
}

func (m *Mdns) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	m.mu.RLock()
	n := m.nodes[tag]
	m.mu.RUnlock()
	if n == nil {
		return nil, nil
	}

	samples := n.server.Traffic(reset)
	if len(samples) == 0 {
		return nil, nil
	}

	out := make([]panel.UserTraffic, 0, len(samples))
	m.mu.RLock()
	for _, s := range samples {
		uid, ok := m.usersMap[s.UUID]
		if !ok {
			continue // user removed since the sample; drop it
		}
		out = append(out, panel.UserTraffic{
			UID:      uid,
			Upload:   s.Upload,
			Download: s.Download,
		})
	}
	m.mu.RUnlock()

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
