package counter

import "sync"

// Departed keeps the counters of users removed from a node, each with the
// user it is billed to, until a report has taken what they hold. A core that
// deleted a removed user's counter lost what they ran up since the node's
// last report: up to a whole report interval of traffic, never billed.
type Departed struct {
	mu    sync.Mutex
	users []departedUser
}

type departedUser struct {
	uid     int
	traffic *TrafficStorage
}

// Final is what a removed user ran up since the node's last report.
type Final struct {
	UID              int
	Upload, Download int64
}

// Keep keeps a removed user's counter for the node's next reports.
func (d *Departed) Keep(uid int, traffic *TrafficStorage) {
	if uid == 0 || traffic == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users = append(d.users, departedUser{uid: uid, traffic: traffic})
}

// Take is what the removed users ran up since the last report, one entry a
// user. With reset it takes the bytes out of the counters, and lets go of a
// counter it found empty: the user's connections are closed with them, and
// nothing counts into it any more.
func (d *Departed) Take(reset bool) []Final {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Final
	kept := d.users[:0]
	for _, u := range d.users {
		up, down := u.traffic.UpCounter.Load(), u.traffic.DownCounter.Load()
		if reset {
			up, down = u.traffic.UpCounter.Swap(0), u.traffic.DownCounter.Swap(0)
		}
		if up+down > 0 {
			merged := false
			for i := range out {
				if out[i].UID == u.uid {
					out[i].Upload += up
					out[i].Download += down
					merged = true
					break
				}
			}
			if !merged {
				out = append(out, Final{UID: u.uid, Upload: up, Download: down})
			}
		}
		if !reset || up+down > 0 {
			kept = append(kept, u)
		}
	}
	for i := len(kept); i < len(d.users); i++ {
		d.users[i] = departedUser{}
	}
	d.users = kept
	return out
}
