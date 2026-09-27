package sing

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
)

// startSing runs a real sing-box core with a shadowsocks node per tag.
func startSing(t *testing.T, tags ...string) (*Sing, map[string]*panel.NodeInfo) {
	t.Helper()
	c, err := New(&conf.CoreConfig{Type: "sing", SingConfig: conf.NewSingConfig()})
	if err != nil {
		t.Fatal(err)
	}
	b := c.(*Sing)
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	infos := map[string]*panel.NodeInfo{}
	for _, tag := range tags {
		ss := &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
		info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
		opts := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}
		if err := b.AddNode(tag, info, opts); err != nil {
			t.Fatalf("AddNode %s: %v", tag, err)
		}
		infos[tag] = info
	}
	return b, infos
}

// 🔴 One subscriber on two nodes of the same core, removed from one of them.
// The uuid -> id map was shared by every node, so the removal erased their id
// everywhere, and the traffic they went on using on the other node was thrown
// away at the next report instead of being billed.
func TestSing_RemovingAUserFromOneNodeKeepsTheirTrafficOnAnother(t *testing.T) {
	b, infos := startSing(t, "A", "B")
	user := []panel.UserInfo{{Id: 7, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}}
	for tag, info := range infos {
		if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: user, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
	}
	b.hookServer.trafficStorages("B", user[0].Uuid, "", false)[0].UpCounter.Add(1000)

	if err := b.DelUsers(user, "A", infos["A"]); err != nil {
		t.Fatal(err)
	}
	got, err := b.GetUserTrafficSlice("B", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].UID != 7 || got[0].Upload != 1000 {
		t.Fatalf("traffic on node B = %+v, want 1000 bytes for UID 7", got)
	}

	// On the node they were removed from, nothing is attributed to them.
	b.hookServer.trafficStorages("A", user[0].Uuid, "", false)[0].UpCounter.Add(500)
	if got, _ := b.GetUserTrafficSlice("A", true); len(got) != 0 {
		t.Fatalf("traffic on node A after removal = %+v, want none", got)
	}
}

// A tcp node with an HTTP header but no path builds (without a path) instead of
// panicking on request.Path[0].
func TestSing_HTTPHeaderWithoutPath(t *testing.T) {
	v := &panel.VAllssNode{
		Network:         "tcp",
		NetworkSettings: []byte(`{"header":{"type":"http","request":{"method":"GET","headers":{"Host":["a.com"]}}}}`),
	}
	info := &panel.NodeInfo{Type: "vless", VAllss: v, Common: &v.CommonNode}
	in, err := getInboundOptions("t", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()})
	if err != nil {
		t.Fatal(err)
	}
	if in.Type != "vless" {
		t.Fatalf("inbound type = %q", in.Type)
	}
}
