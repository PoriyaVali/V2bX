package sing

import (
	"testing"

	"github.com/PoriyaVali/V2bX/common/counter"
)

// The whole point of the per-device ledger: a user whose carrier hands out a
// different egress address per connection must not be counted as many devices.
// Only the addresses that actually moved traffic past the threshold should
// survive, and the user's own total must stay untouched.
func TestDeviceTrafficSeparatesRealDevicesFromRotatedAddresses(t *testing.T) {
	h := &HookServer{}
	const tag = "inbound-1"
	const user = "uuid-a"

	// One busy address plus a pool of transient ones, exactly the shape seen on
	// the live node: sixteen addresses inside one carrier range, one of them
	// doing the work.
	busy := h.trafficStorages(tag, user, "5.127.1.1", true)
	if len(busy) != 2 {
		t.Fatalf("expected a user ledger and a device ledger, got %d", len(busy))
	}
	busy[1].UpCounter.Add(900_000)
	busy[0].UpCounter.Add(900_000) // the user's own total

	for _, ip := range []string{"5.127.1.2", "5.127.1.3", "5.127.1.4"} {
		s := h.trafficStorages(tag, user, ip, true)
		s[1].UpCounter.Add(4_000) // a few kilobytes, the way a short-lived session looks
		s[0].UpCounter.Add(4_000)
	}

	uidOf := func(uuid string) int {
		if uuid == user {
			return 42
		}
		return 0
	}

	got := h.GetDeviceTraffic(tag, uidOf, true)
	if len(got[42]) != 4 {
		t.Fatalf("expected all four addresses reported with their own totals, got %v", got[42])
	}
	if got[42]["5.127.1.1"] != 900_000 {
		t.Errorf("busy address = %d, want 900000", got[42]["5.127.1.1"])
	}
	if got[42]["5.127.1.2"] != 4_000 {
		t.Errorf("transient address = %d, want 4000", got[42]["5.127.1.2"])
	}

	// A 256 KB threshold, applied per address, leaves only the real device.
	const threshold = 256 * 1000
	kept := 0
	for _, n := range got[42] {
		if n >= threshold {
			kept++
		}
	}
	if kept != 1 {
		t.Errorf("threshold kept %d addresses, want 1 - the rotating pool must collapse to the device doing the work", kept)
	}
}

// Reset must zero the counters without dropping the entry, or a live connection
// - which holds a pointer to its storage - would keep counting into an orphan
// while the next read created a fresh zero and declared the device idle.
func TestDeviceTrafficResetKeepsLiveEntriesUsable(t *testing.T) {
	h := &HookServer{}
	const tag, user, ip = "inbound-1", "uuid-a", "1.2.3.4"
	uidOf := func(string) int { return 7 }

	s := h.trafficStorages(tag, user, ip, true)
	s[1].UpCounter.Add(500_000)

	h.GetDeviceTraffic(tag, uidOf, true)

	// The same storage the "connection" still holds must be the one a later read
	// sees, so traffic after the reset is not lost.
	s[1].DownCounter.Add(300_000)
	got := h.GetDeviceTraffic(tag, uidOf, true)
	if got[7][ip] != 300_000 {
		t.Fatalf("after reset the live storage reported %d, want 300000", got[7][ip])
	}
}

// Silent addresses have to go eventually or the map grows for every address a
// rotating carrier ever used - but not on the first quiet cycle.
func TestDeviceTrafficEvictsOnlyAfterSustainedSilence(t *testing.T) {
	h := &HookServer{}
	const tag, user, ip = "inbound-1", "uuid-a", "9.9.9.9"
	uidOf := func(string) int { return 7 }

	h.trafficStorages(tag, user, ip, true)[1].UpCounter.Add(1_000)
	h.GetDeviceTraffic(tag, uidOf, true) // seen, then reset to zero

	for i := 0; i < deviceIdleCycles-1; i++ {
		h.GetDeviceTraffic(tag, uidOf, true)
	}
	d, _ := h.deviceCounter.Load(tag)
	if _, still := d.(*counter.TrafficCounter).Counters.Load(deviceKey(user, ip)); !still {
		t.Fatal("entry evicted too early - a device that pauses briefly would vanish")
	}

	h.GetDeviceTraffic(tag, uidOf, true)
	if _, still := d.(*counter.TrafficCounter).Counters.Load(deviceKey(user, ip)); still {
		t.Error("entry survived sustained silence - the map would grow without bound")
	}
}

// The node's own addresses are not devices; asking for their ledger must return
// the user's alone, so they can never be reported as an online device.
func TestNodeOwnedSourceGetsNoDeviceLedger(t *testing.T) {
	h := &HookServer{}
	if got := len(h.trafficStorages("t", "u", "10.0.0.1", false)); got != 1 {
		t.Errorf("countDevice=false produced %d ledgers, want 1 (user only)", got)
	}
	if got := len(h.trafficStorages("t", "u", "", true)); got != 1 {
		t.Errorf("empty address produced %d ledgers, want 1 (user only)", got)
	}
}

// uuid|ip must survive a round trip, including IPv6 literals full of colons.
func TestDeviceKeyRoundTrip(t *testing.T) {
	for _, ip := range []string{"1.2.3.4", "2001:db8::1", "::ffff:5.6.7.8"} {
		uuid, got, ok := splitDeviceKey(deviceKey("uuid-a", ip))
		if !ok || uuid != "uuid-a" || got != ip {
			t.Errorf("round trip of %q gave (%q, %q, %v)", ip, uuid, got, ok)
		}
	}
}
