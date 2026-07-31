package core

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
)

// A core that answers for itself, standing in for mdns.
type selfReportingCore struct {
	online     []panel.OnlineUser
	limitCalls []panel.UserInfo
}

func (c *selfReportingCore) OnlineDevices(string) ([]panel.OnlineUser, error) {
	return c.online, nil
}

func (c *selfReportingCore) UpdateUserLimits(_ string, users []panel.UserInfo) {
	c.limitCalls = append(c.limitCalls, users...)
}

// A core that knows neither method, standing in for xray/hysteria2.
type plainCore struct{}

// 🔴 This is the failure mode that has already cost a day once: every node here
// runs a selector, so the controller holds a *Selector and reaches the core
// through a type assertion. A method missing from this type does not fail to
// build and does not log - the assertion just returns false and the feature is
// silently dead. GetDeviceTrafficSlice was exactly this. These two are the same
// shape, so they get the same guard.
func TestSelectorForwardsOnlineDevicesToTheOwningCore(t *testing.T) {
	s := &Selector{}
	want := []panel.OnlineUser{{UID: 9, IP: "5.127.0.1"}}
	s.nodes.Store("tag-mdns", &selfReportingCore{online: want})

	got, err := s.OnlineDevices("tag-mdns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].UID != 9 || got[0].IP != "5.127.0.1" {
		t.Fatalf("the core's devices did not come through the selector: %v", got)
	}
}

func TestSelectorForwardsLimitChangesToTheOwningCore(t *testing.T) {
	s := &Selector{}
	core := &selfReportingCore{}
	s.nodes.Store("tag-mdns", core)

	s.UpdateUserLimits("tag-mdns", []panel.UserInfo{{Id: 3, Uuid: "u3", SpeedLimit: 40}})

	if len(core.limitCalls) != 1 || core.limitCalls[0].SpeedLimit != 40 {
		t.Fatalf("the limit change never reached the core: %+v", core.limitCalls)
	}
}

// Cores that do not implement these must be left alone, not error and not panic:
// they get their limits from the limiter and their addresses from CheckLimit.
func TestSelectorIsSilentForCoresThatDoNotImplementThem(t *testing.T) {
	s := &Selector{}
	s.nodes.Store("tag-xray", &plainCore{})

	got, err := s.OnlineDevices("tag-xray")
	if err != nil || got != nil {
		t.Errorf("expected nothing for a core without the method, got %v / %v", got, err)
	}
	s.UpdateUserLimits("tag-xray", []panel.UserInfo{{Id: 1}}) // must not panic
}

// An unknown tag must not panic either - a node can be torn down between the
// poll that scheduled the report and the report itself.
func TestSelectorHandlesAnUnknownTag(t *testing.T) {
	s := &Selector{}
	if _, err := s.OnlineDevices("missing"); err == nil {
		t.Error("expected an error for an unknown tag")
	}
	s.UpdateUserLimits("missing", []panel.UserInfo{{Id: 1}}) // must not panic
}
