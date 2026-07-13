package limiter

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
)

// Behind the Hedioum tunnel the foreign egress dials the local inbound, so every
// tunneled user reaches the core with a source of 127.0.0.1. core/sing passes
// countDevice=false for such a source (localip.IsNodeOwned), which is what stops
// the node counting *itself* as an extra device — the bug that used to lock out
// device_limit=1 users.
//
// These two pin down exactly what that costs and what it does not, because the
// distinction decides whether a tunneled node needs PROXY protocol
// (SingOptions.ProxyProtocol + the foreign end's -proxy-protocol) to enforce
// device limits: SPEED limits survive the tunnel, DEVICE limits do not.

// A tunneled connection is still speed-limited: the bucket is computed after the
// device-counting branch, so it does not depend on the source address.
func TestTunnel_SpeedLimitStillAppliesToLoopbackSource(t *testing.T) {
	Init()
	const tag = "tunnel-node"
	l := AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 10}}, map[int]int{})
	t.Cleanup(func() { DeleteLimiter(tag) })
	tu := format.UserTag(tag, "u1")

	// countDevice=false — exactly what core/sing passes for a 127.0.0.1 source.
	b, reject := l.CheckLimit(tu, "127.0.0.1", true, false)
	if reject {
		t.Fatal("a tunneled connection must not be rejected")
	}
	if b == nil || b.Capacity() != 10*1000000/8 {
		t.Fatalf("tunneled user lost their speed limit: bucket = %v", b)
	}
}

// ...but a tunneled connection is NOT counted as a device: it registers no
// online IP, so the panel shows nothing for it and device_limit cannot bite.
// Recovering this needs the real client IP (PROXY protocol), not a limiter change.
func TestTunnel_LoopbackSourceIsNeitherCountedNorLimited(t *testing.T) {
	Init()
	const tag = "tunnel-node-2"
	l := AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "u1", DeviceLimit: 1}}, map[int]int{1: 99})
	t.Cleanup(func() { DeleteLimiter(tag) })
	tu := format.UserTag(tag, "u1")

	// Far over the device limit (alive=99, limit=1) — yet admitted, because the
	// source is the node itself and the device check is skipped entirely.
	if _, reject := l.CheckLimit(tu, "127.0.0.1", true, false); reject {
		t.Fatal("a loopback source must never be device-limited (it is the tunnel, not a user device)")
	}
	if _, ok := l.UserOnlineIP.Load(tu); ok {
		t.Fatal("a loopback source must not be registered as an online IP")
	}
	online, _ := l.GetOnlineDevice()
	if len(*online) != 0 {
		t.Fatalf("a tunneled user must not appear in the online report, got %v", *online)
	}
}

// With PROXY protocol enabled the core hands us the real client IP instead, and
// the node behaves exactly like a direct one: counted, reported, limited.
func TestTunnel_WithRealClientIP_DeviceLimitWorksAgain(t *testing.T) {
	Init()
	const tag = "tunnel-node-3"
	l := AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "u1", DeviceLimit: 1}}, map[int]int{1: 0})
	t.Cleanup(func() { DeleteLimiter(tag) })
	tu := format.UserTag(tag, "u1")

	// countDevice=true — the source is now the user's real address.
	if _, reject := l.CheckLimit(tu, "5.213.230.219", true, true); reject {
		t.Fatal("first real device must be admitted")
	}
	online, _ := l.GetOnlineDevice()
	if len(*online) != 1 || (*online)[0].IP != "5.213.230.219" {
		t.Fatalf("the real client IP must be reported online, got %v", *online)
	}
	l.SetAliveList(map[int]int{1: 1}) // panel now counts that device
	if _, reject := l.CheckLimit(tu, "9.9.9.9", true, true); !reject {
		t.Fatal("a second device over device_limit=1 must be rejected")
	}
}
