package core

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
)

type retiringOwner struct {
	placeCore
	retired bool
}

func (r *retiringOwner) RetireNode(string) ([]panel.UserTraffic, error) {
	r.retired = true
	return []panel.UserTraffic{{UID: 7, Upload: 3, Download: 4}}, nil
}

func TestSelectorRetiresBeforeDeletingOwnerMapping(t *testing.T) {
	owner := &retiringOwner{}
	selector := &Selector{}
	selector.nodes.Store("retiring", owner)
	traffic, err := selector.RetireNode("retiring")
	if err != nil || !owner.retired || len(traffic) != 1 || traffic[0].UID != 7 || traffic[0].Download != 4 {
		t.Fatalf("owning core's final traffic was not forwarded: %+v %v", traffic, err)
	}
	if _, exists := selector.nodes.Load("retiring"); exists {
		t.Fatal("retired node retained an active selector mapping")
	}
	if _, err := selector.RetireNode("retiring"); err == nil {
		t.Fatal("retired node could be collected twice")
	}
}
