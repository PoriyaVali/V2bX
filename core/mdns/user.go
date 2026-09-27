package mdns

import (
	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
)

func (m *Mdns) AddUsers(p *vCore.AddUsersParams) (added int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[p.Tag]
	users := m.users[p.Tag]
	if users == nil {
		users = make(map[string]int, len(p.Users))
		m.users[p.Tag] = users
	}
	for _, u := range p.Users {
		users[u.Uuid] = u.Id
		if n != nil {
			n.server.AddUser(u.Uuid)
			n.server.SetUserSpeedLimit(u.Uuid, speedLimitBytes(u.SpeedLimit))
		}
	}
	return len(p.Users), nil
}

// speedLimitBytes converts the panel's Mbit/s into bytes per second, matching
// what limiter.CheckLimit computes for every other core, so a subscriber is
// paced the same wherever they land. Zero stays zero, which means unlimited.
func speedLimitBytes(mbps int) int64 {
	if mbps <= 0 {
		return 0
	}
	return int64(mbps) * 1000000 / 8
}

// UpdateUserLimits re-applies speed limits to users already on the node.
//
// Every other core reaches its limits through limiter.CheckLimit on each
// connection, so a change there is picked up on the next one. This core never
// calls the limiter - the tunnel paces itself - so without this an edit in the
// panel would only apply to users who joined afterwards, and a subscriber whose
// plan changed would keep their old speed indefinitely.
func (m *Mdns) UpdateUserLimits(tag string, users []panel.UserInfo) {
	m.mu.RLock()
	n := m.nodes[tag]
	m.mu.RUnlock()
	if n == nil {
		return
	}
	for i := range users {
		n.server.SetUserSpeedLimit(users[i].Uuid, speedLimitBytes(users[i].SpeedLimit))
	}
}

// OnlineDevices reports the source addresses currently seen for each user, in
// the shape the panel's online report expects.
//
// The limiter supplies this for the other cores and never sees an mdns
// connection - which is why an mdns node reported no devices at all, and why a
// device limit could not be enforced on one. The addresses come from the tunnel
// itself, recorded at the authenticated handshake.
func (m *Mdns) OnlineDevices(tag string) ([]panel.OnlineUser, error) {
	m.mu.RLock()
	n := m.nodes[tag]
	m.mu.RUnlock()
	if n == nil {
		return nil, nil
	}
	byUUID := n.server.OnlineIPs()
	if len(byUUID) == 0 {
		return nil, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return onlineUsers(byUUID, m.users[tag]), nil
}

// GetDeviceTrafficSlice reports bytes carried per user, per address, since the
// last call.
//
// Without it the controller falls back to a per-user threshold, and that
// fallback is what locked customers out of their own accounts: pass the
// threshold once and every address the user was seen from is reported, so one
// phone behind a carrier that rotates its egress address per query is counted
// as a dozen devices. Answering per address lets the controller judge each one
// on its own traffic.
func (m *Mdns) GetDeviceTrafficSlice(tag string, reset bool) (map[int]map[string]int64, error) {
	m.mu.RLock()
	n := m.nodes[tag]
	m.mu.RUnlock()
	if n == nil {
		return nil, nil
	}
	byUUID := n.server.OnlineIPTraffic(reset)
	if len(byUUID) == 0 {
		return nil, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return deviceTraffic(byUUID, m.users[tag]), nil
}

// deviceTraffic re-keys the tunnel's per-address totals from UUID to panel UID,
// dropping users the node no longer knows rather than charging their traffic to
// whichever account holds UID 0.
func deviceTraffic(byUUID map[string]map[string]int64, uids map[string]int) map[int]map[string]int64 {
	out := make(map[int]map[string]int64, len(byUUID))
	for uuid, perAddr := range byUUID {
		uid, ok := uids[uuid]
		if !ok {
			continue
		}
		dst, exists := out[uid]
		if !exists {
			dst = make(map[string]int64, len(perAddr))
			out[uid] = dst
		}
		for ip, n := range perAddr {
			dst[ip] += n
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// onlineUsers turns the tunnel's UUID-keyed addresses into the panel's UID/IP
// pairs, one entry per address so a user holding several devices is counted as
// several. A UUID with no UID is dropped rather than reported as user 0, which
// would attribute a stranger's device to whichever account holds that ID.
func onlineUsers(byUUID map[string][]string, uids map[string]int) []panel.OnlineUser {
	out := make([]panel.OnlineUser, 0, len(byUUID))
	for uuid, ips := range byUUID {
		uid, ok := uids[uuid]
		if !ok {
			continue // removed between the sample and this read
		}
		for _, ip := range ips {
			out = append(out, panel.OnlineUser{UID: uid, IP: ip})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (m *Mdns) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.nodes[tag]
	for _, u := range users {
		delete(m.users[tag], u.Uuid)
		delete(m.carried[tag], u.Uuid)
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
		// Mid-reload: what the old tunnel counted is carried, and goes out
		// once the node is back.
		return nil, nil
	}

	totals := make(map[string][2]int64)
	for _, s := range n.server.Traffic(reset) {
		v := totals[s.UUID]
		v[0] += s.Upload
		v[1] += s.Download
		totals[s.UUID] = v
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	carried := m.carried[tag]
	for uuid, v := range carried {
		t := totals[uuid]
		t[0] += v[0]
		t[1] += v[1]
		totals[uuid] = t
	}
	if len(totals) == 0 {
		return nil, nil
	}
	users := m.users[tag]
	out := make([]panel.UserTraffic, 0, len(totals))
	for uuid, v := range totals {
		uid, ok := users[uuid]
		if !ok {
			// Removed since the sample (DelUsers also drops what was carried
			// for them), or re-added a moment from now after a reload - in
			// which case what was carried waits for the next report.
			continue
		}
		out = append(out, panel.UserTraffic{
			UID:      uid,
			Upload:   v[0],
			Download: v[1],
		})
		if reset {
			delete(carried, uuid)
		}
	}
	if len(carried) == 0 {
		delete(m.carried, tag)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
