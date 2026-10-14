//go:build soak && with_quic

package sing

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
)

func TestTUICInvalidUUIDDoesNotPoisonLaterUserUpdates(t *testing.T) {
	b, _ := startSing(t)
	cert, key := writeSelfSigned(t, t.TempDir())
	tuic := &panel.TuicNode{}
	info := &panel.NodeInfo{Type: "tuic", Security: panel.Tls, Tuic: tuic, Common: &tuic.CommonNode}
	options := &conf.Options{
		ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions(),
		CertConfig: &conf.CertConfig{CertMode: "file", CertFile: cert, KeyFile: key},
	}
	if err := b.AddNode("tuic-users", info, options); err != nil {
		t.Fatal(err)
	}
	invalid := []panel.UserInfo{{Id: 17, Uuid: "not-a-uuid"}}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "tuic-users", Users: invalid, NodeInfo: info}); err == nil {
		t.Fatal("invalid TUIC UUID accepted")
	}
	if len(b.users.uidMap) != 0 {
		t.Fatal("failed TUIC update published user identity")
	}
	valid := []panel.UserInfo{{Id: 18, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "tuic-users", Users: valid, NodeInfo: info}); err != nil {
		t.Fatalf("invalid UUID poisoned later valid TUIC update: %v", err)
	}
}
