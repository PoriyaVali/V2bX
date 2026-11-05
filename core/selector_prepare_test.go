package core

import (
	"errors"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

// preparingCore is a placeCore that also prepares nodes, and records which.
type preparingCore struct {
	placeCore
	prepared []string
	err      error
}

func (c *preparingCore) PrepareNode(tag string, _ *panel.NodeInfo, _ *conf.Options) error {
	c.prepared = append(c.prepared, tag)
	return c.err
}

// A reload prepares on the core AddNode is about to place the node on, chosen
// the same way, and on no other.
func TestSelectorPrepareNode_UsesTheCoreAddNodeWouldPick(t *testing.T) {
	sing := &placeCore{typ: "sing", protocols: []string{"vless", "trojan"}}
	tt := &preparingCore{placeCore: placeCore{typ: "trusttunnel", protocols: []string{"trusttunnel"}}}
	other := &preparingCore{placeCore: placeCore{typ: "mihomo", protocols: []string{"trusttunnel", "vless"}}}
	s := &Selector{
		cores: map[string]Core{"sing": sing, "trusttunnel": tt, "mihomo": other},
		order: []string{"sing", "trusttunnel", "mihomo"},
	}

	// By protocol, first in config order: trusttunnel before mihomo.
	if err := s.PrepareNode("a", &panel.NodeInfo{Type: "trusttunnel"}, &conf.Options{}); err != nil {
		t.Fatal(err)
	}
	// Pinned by an earlier placement.
	if err := s.PrepareNode("b", &panel.NodeInfo{Type: "trusttunnel"}, &conf.Options{Core: "mihomo"}); err != nil {
		t.Fatal(err)
	}
	// By name.
	if err := s.PrepareNode("c", &panel.NodeInfo{Type: "trusttunnel"}, &conf.Options{CoreName: "mihomo"}); err != nil {
		t.Fatal(err)
	}
	if len(tt.prepared) != 1 || tt.prepared[0] != "a" || len(other.prepared) != 2 {
		t.Fatalf("prepared on the wrong core: trusttunnel %v, mihomo %v", tt.prepared, other.prepared)
	}
	// A core with nothing to prepare, and a node no core serves, are fine:
	// there is nothing to do ahead, and AddNode reports the unsupported node.
	if err := s.PrepareNode("d", &panel.NodeInfo{Type: "vless"}, &conf.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareNode("e", &panel.NodeInfo{Type: "unknown"}, &conf.Options{}); err != nil {
		t.Fatal(err)
	}
	if len(sing.got) != 0 || len(tt.got) != 0 || len(other.got) != 0 {
		t.Fatal("preparing placed a node")
	}

	tt.err = errors.New("authority unreachable")
	if err := s.PrepareNode("a", &panel.NodeInfo{Type: "trusttunnel"}, &conf.Options{}); !errors.Is(err, tt.err) {
		t.Fatalf("a failed preparation was not reported: %v", err)
	}
}
