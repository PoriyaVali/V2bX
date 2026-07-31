package limiter

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
)

// A user already at their limit across the fleet must not get another device.
func TestAdmitDevice_OverTheFleetWideLimit_Refused(t *testing.T) {
	l, key := newTestLimiter(2, 2)
	if l.AdmitDevice(key, "5.127.0.9") {
		t.Error("admitted a third device for a user limited to two")
	}
}

func TestAdmitDevice_UnderTheLimit_Allowed(t *testing.T) {
	l, key := newTestLimiter(3, 1)
	if !l.AdmitDevice(key, "5.127.0.9") {
		t.Error("refused a second device for a user limited to three")
	}
}

// device_limit 0 means unlimited and must never refuse.
func TestAdmitDevice_ZeroMeansUnlimited(t *testing.T) {
	l, key := newTestLimiter(0, 99)
	if !l.AdmitDevice(key, "5.127.0.9") {
		t.Error("a user with no device limit was refused")
	}
}

// 🔴 This must NOT register the address. A core that answers for its own
// connections reports them itself; if the limiter recorded them too, every
// address would appear twice in the online report and the panel would read
// double the devices - locking out the users this is meant to protect.
func TestAdmitDevice_LeavesNoTraceInTheOnlineMap(t *testing.T) {
	l, key := newTestLimiter(5, 0)
	l.AdmitDevice(key, "5.127.0.9")
	if n := onlineIPCount(l, key); n != 0 {
		t.Errorf("the address was registered (%d entries); it would be reported twice", n)
	}
}

// Membership is proven by the caller - an mdns handshake carries an HMAC token
// that must match a registered user. Refusing on absence would turn a moment's
// lag between the limiter's user list and the core's into a refused connection
// for a paying subscriber. This is the one place AdmitDevice and CheckLimit
// deliberately disagree.
func TestAdmitDevice_UnknownUserIsAdmitted(t *testing.T) {
	l, _ := newTestLimiter(2, 0)
	if !l.AdmitDevice("test-node|not-registered-yet", "5.127.0.9") {
		t.Error("refused a user the limiter does not know about yet")
	}
	var nilLimiter *Limiter
	if !nilLimiter.AdmitDevice("tag|u", "1.1.1.1") {
		t.Error("a nil limiter refused instead of admitting")
	}
}

// The grace list rescues a device across a restart, but only its own user's -
// matching CheckLimit, where admitting on a bare IP let a DIFFERENT user in
// over their limit whenever the two shared a public address (routine on CGNAT).
func TestAdmitDevice_GraceListIsMatchedToTheUser(t *testing.T) {
	Init()
	tag := "grace-node"
	users := []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
		{Id: 2, Uuid: "u2", DeviceLimit: 1},
	}
	l := AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{1: 1, 2: 1})
	l.OldUserOnline.Store("5.127.0.9", 1)

	if l.AdmitDevice(format.UserTag(tag, "u2"), "5.127.0.9") {
		t.Error("user 2 was let in on user 1's grace entry for a shared address")
	}
	if !l.AdmitDevice(format.UserTag(tag, "u1"), "5.127.0.9") {
		t.Error("user 1 was refused their own grace entry")
	}
}

// IPv4-mapped IPv6 must match the plain form, or a returning device looks new.
func TestAdmitDevice_MappedAddressMatchesThePlainForm(t *testing.T) {
	l, key := newTestLimiter(1, 1)
	l.OldUserOnline.Store("5.127.0.9", 1)
	if !l.AdmitDevice(key, "::ffff:5.127.0.9") {
		t.Error("the mapped form did not match the grace entry for the same device")
	}
}
