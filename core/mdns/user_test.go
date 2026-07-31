package mdns

import (
	"sort"
	"testing"
)

// The panel sends Mbit/s. Every other core turns that into bytes per second the
// same way inside limiter.CheckLimit, so a subscriber on 40 Mbit gets 40 Mbit
// wherever they land. Getting the unit wrong here would not fail to build or
// log anything - it would just quietly hand out the wrong speed.
func TestSpeedLimitMatchesTheLimitersConversion(t *testing.T) {
	cases := map[int]int64{
		0:    0,       // unlimited
		-1:   0,       // never negative, which would mean "stop entirely"
		1:    125_000, // 1 Mbit/s
		40:   5_000_000,
		1000: 125_000_000,
	}
	for mbps, want := range cases {
		if got := speedLimitBytes(mbps); got != want {
			t.Errorf("%d Mbit/s -> %d bytes/s, want %d", mbps, got, want)
		}
	}
}

// Each address is its own device: a user on a phone and a laptop must reach the
// panel as two entries, or the device limit they are paying for cannot count.
func TestOnlineUsersReportsOneEntryPerAddress(t *testing.T) {
	got := onlineUsers(
		map[string][]string{"uuid-a": {"5.127.0.1", "5.127.0.2"}},
		map[string]int{"uuid-a": 77},
	)
	if len(got) != 2 {
		t.Fatalf("expected 2 devices, got %v", got)
	}
	ips := []string{got[0].IP, got[1].IP}
	sort.Strings(ips)
	if ips[0] != "5.127.0.1" || ips[1] != "5.127.0.2" {
		t.Errorf("addresses came through wrong: %v", ips)
	}
	for _, u := range got {
		if u.UID != 77 {
			t.Errorf("device attributed to UID %d, want 77", u.UID)
		}
	}
}

// 🔴 A UUID the node no longer knows must be dropped, not reported as UID 0.
// The map lookup returns the zero value on a miss, so reporting it unchecked
// would charge a stranger's device to whichever real account holds ID 0's slot.
func TestOnlineUsersDropsUnknownUUIDs(t *testing.T) {
	got := onlineUsers(
		map[string][]string{
			"known":   {"1.1.1.1"},
			"removed": {"2.2.2.2"},
		},
		map[string]int{"known": 5},
	)
	if len(got) != 1 {
		t.Fatalf("expected only the known user, got %v", got)
	}
	if got[0].UID != 5 || got[0].IP != "1.1.1.1" {
		t.Errorf("wrong entry survived: %+v", got[0])
	}
}

// Nothing online must produce nothing, not an empty non-nil report: the caller
// checks the length before deciding whether to contact the panel at all.
func TestOnlineUsersReturnsNilWhenNobodyMatches(t *testing.T) {
	if got := onlineUsers(map[string][]string{"gone": {"1.1.1.1"}}, map[string]int{}); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// Per-address totals must arrive keyed by the panel's UID, or the controller's
// per-device gate has nothing to match its online report against and silently
// falls back to the per-user one - the fallback that caused the lockouts.
func TestDeviceTrafficIsRekeyedToPanelUIDs(t *testing.T) {
	got := deviceTraffic(
		map[string]map[string]int64{
			"uuid-a": {"5.127.0.1": 9_000_000, "5.127.0.2": 300},
		},
		map[string]int{"uuid-a": 12},
	)
	if got[12]["5.127.0.1"] != 9_000_000 || got[12]["5.127.0.2"] != 300 {
		t.Fatalf("per-address totals came through wrong: %v", got)
	}
}

// 🔴 A UUID the node no longer knows must be dropped. Reporting it would charge
// a stranger's traffic to whichever account happens to hold UID 0.
func TestDeviceTrafficDropsUnknownUUIDs(t *testing.T) {
	got := deviceTraffic(
		map[string]map[string]int64{"removed": {"2.2.2.2": 500}},
		map[string]int{"known": 5},
	)
	if got != nil {
		t.Errorf("expected nothing, got %v", got)
	}
}
