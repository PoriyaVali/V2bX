package sing

import (
	"testing"

	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/format"
)

func TestOnlineDevicesRetainsEstablishedAddressesUntilLastClose(t *testing.T) {
	h := &HookServer{}
	uidOf := func(uuid string) int {
		if uuid == "u" {
			return 7
		}
		return 0
	}
	first, result := h.register(format.UserTag("in", "u"), &nopCloser{}, 0, "5.5.5.5")
	if result != registered {
		t.Fatal(result)
	}
	second, _ := h.register(format.UserTag("in", "u"), &nopCloser{}, 0, "5.5.5.5")
	other, _ := h.register(format.UserTag("other", "u"), &nopCloser{}, 0, "6.6.6.6")
	defer other()
	for i := 0; i < 4; i++ {
		online := h.OnlineDevices("in", uidOf)
		if len(online) != 1 || online[0].UID != 7 || online[0].IP != "5.5.5.5" {
			t.Fatalf("cycle %d: snapshot = %v", i, online)
		}
	}
	first()
	if len(h.OnlineDevices("in", uidOf)) != 1 {
		t.Fatal("closing one of two connections removed the device")
	}
	second()
	if got := h.OnlineDevices("in", uidOf); len(got) != 0 {
		t.Fatalf("device remained after its last connection closed: %v", got)
	}
}

func TestDeviceTrafficKeepsSilentLiveStorageAndEvictsAfterClose(t *testing.T) {
	h := &HookServer{}
	const tag, uuid, ip = "in", "u", "5.5.5.5"
	uidOf := func(string) int { return 7 }
	release, _ := h.register(format.UserTag(tag, uuid), &nopCloser{}, 0, ip)
	storage := h.trafficStorages(tag, uuid, ip, true)[1]
	for i := 0; i < 2*deviceIdleCycles; i++ {
		h.GetDeviceTraffic(tag, uidOf, true)
	}
	storage.UpCounter.Add(1234)
	if got := h.GetDeviceTraffic(tag, uidOf, true)[7][ip]; got != 1234 {
		t.Fatalf("idle connection counted into an orphaned storage: got %d", got)
	}
	release()
	for i := 0; i < deviceIdleCycles; i++ {
		h.GetDeviceTraffic(tag, uidOf, true)
	}
	v, _ := h.deviceCounter.Load(tag)
	if _, exists := v.(*counter.TrafficCounter).Counters.Load(deviceKey(uuid, ip)); exists {
		t.Fatal("closed device retained its per-IP counter after sustained silence")
	}
}

func TestDeviceIdleAgeIsScopedToNode(t *testing.T) {
	h := &HookServer{}
	uidOf := func(string) int { return 7 }
	for _, tag := range []string{"a", "b"} {
		h.trafficStorages(tag, "u", "5.5.5.5", true)
	}
	// Two quiet polls per node are still below the eviction threshold; the
	// shared UUID/IP must not make one node advance the other node's idle age.
	for i := 0; i < deviceIdleCycles-1; i++ {
		for _, tag := range []string{"a", "b"} {
			h.GetDeviceTraffic(tag, uidOf, true)
		}
	}
	for _, tag := range []string{"a", "b"} {
		v, _ := h.deviceCounter.Load(tag)
		if _, exists := v.(*counter.TrafficCounter).Counters.Load(deviceKey("u", "5.5.5.5")); !exists {
			t.Fatalf("node %s inherited another node's idle age", tag)
		}
	}
}
