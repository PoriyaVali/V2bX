package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

// placeCore is a core that accepts any node for its protocols and records the
// options each AddNode received.
type placeCore struct {
	typ       string
	protocols []string
	got       []*conf.Options
}

func (c *placeCore) Start() error { return nil }
func (c *placeCore) Close() error { return nil }
func (c *placeCore) AddNode(_ string, _ *panel.NodeInfo, o *conf.Options) error {
	c.got = append(c.got, o)
	return nil
}
func (c *placeCore) DelNode(string) error                                     { return nil }
func (c *placeCore) AddUsers(p *AddUsersParams) (int, error)                  { return len(p.Users), nil }
func (c *placeCore) DelUsers([]panel.UserInfo, string, *panel.NodeInfo) error { return nil }
func (c *placeCore) GetUserTrafficSlice(string, bool) ([]panel.UserTraffic, error) {
	return nil, nil
}
func (c *placeCore) Protocols() []string { return c.protocols }
func (c *placeCore) Type() string        { return c.typ }

func nodeOptions(t *testing.T, raw string) *conf.Options {
	t.Helper()
	var nc conf.NodeConfig
	if err := json.Unmarshal([]byte(raw), &nc); err != nil {
		t.Fatal(err)
	}
	return &nc.Options
}

// 🔴 A node on a core without options of its own (mdns, trusttunnel) has to
// survive being re-added - that is what every reload of the node does. The
// second AddNode used to fail with "unexpected end of JSON input", and the node
// stayed down.
func TestSelectorAddNode_ReAddsANodeOnACoreWithoutOptions(t *testing.T) {
	for _, core := range []string{"mdns", "trusttunnel"} {
		t.Run(core, func(t *testing.T) {
			opts := nodeOptions(t, `{"Core":"`+core+`","ApiHost":"x","NodeID":1,"NodeType":"`+core+`"}`)
			s := &Selector{
				cores: map[string]Core{core: &placeCore{typ: core, protocols: []string{core}}, "sing": &placeCore{typ: "sing", protocols: []string{"vless"}}},
				order: []string{"sing", core},
			}
			info := &panel.NodeInfo{Type: core}
			for i := 1; i <= 3; i++ {
				if err := s.AddNode("t", info, opts); err != nil {
					t.Fatalf("AddNode #%d: %v", i, err)
				}
				if err := s.DelNode("t"); err != nil {
					t.Fatalf("DelNode #%d: %v", i, err)
				}
			}
		})
	}
}

// A node config that does not name its core still gets that core's options
// parsed - a lone core used to receive them unset and crash on a nil pointer.
func TestSelectorAddNode_ParsesOptionsForTheChosenCore(t *testing.T) {
	sing := &placeCore{typ: "sing", protocols: []string{"vless"}}
	s := &Selector{cores: map[string]Core{"sing": sing}, order: []string{"sing"}}

	opts := nodeOptions(t, `{"ApiHost":"x","NodeID":1,"NodeType":"vless","EnableTFO":true}`)
	if err := s.AddNode("t", &panel.NodeInfo{Type: "vless"}, opts); err != nil {
		t.Fatal(err)
	}
	if len(sing.got) != 1 || sing.got[0].SingOptions == nil || !sing.got[0].SingOptions.TCPFastOpen {
		t.Fatalf("sing core got options %+v, want parsed SingOptions with EnableTFO", sing.got[0])
	}

	// Options built in code, with no JSON behind them at all.
	if err := s.AddNode("t2", &panel.NodeInfo{Type: "vless"}, &conf.Options{}); err != nil {
		t.Fatal(err)
	}
	if sing.got[1].SingOptions == nil {
		t.Fatal("options without JSON must still get the core's defaults")
	}
}

// When two cores can serve a protocol, the first one in the config wins, every
// time. It used to depend on map iteration order.
func TestSelectorAddNode_ChoiceFollowsConfigOrder(t *testing.T) {
	for i := 0; i < 50; i++ {
		xray := &placeCore{typ: "xray", protocols: []string{"vless"}}
		sing := &placeCore{typ: "sing", protocols: []string{"vless"}}
		s := &Selector{cores: map[string]Core{"xray": xray, "sing": sing}, order: []string{"xray", "sing"}}
		if err := s.AddNode("t", &panel.NodeInfo{Type: "vless"}, &conf.Options{}); err != nil {
			t.Fatal(err)
		}
		if len(xray.got) != 1 || len(sing.got) != 0 {
			t.Fatalf("run %d: node went to the second core in the config", i)
		}
	}
}

// NewCore goes through the selector for a single core too, and matches the
// type case-insensitively like the selector does.
func TestNewCore_SingleCoreUsesTheSelector(t *testing.T) {
	RegisterCore("probecore", func(*conf.CoreConfig) (Core, error) {
		return &placeCore{typ: "probecore", protocols: []string{"vless"}}, nil
	})
	defer delete(cores, "probecore")

	c, err := NewCore([]conf.CoreConfig{{Type: "ProbeCore"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(*Selector); !ok {
		t.Fatalf("NewCore returned %T, want *Selector", c)
	}
	if !strings.Contains(c.Type(), "ProbeCore") {
		t.Fatalf("Type() = %q", c.Type())
	}
}
