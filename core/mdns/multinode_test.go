package mdns

import (
	"net"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func mdnsWithNodes(t *testing.T, users []panel.UserInfo, tags ...string) *Mdns {
	t.Helper()
	c, _ := New(nil)
	m := c.(*Mdns)
	t.Cleanup(func() { _ = m.Close() })
	for _, tag := range tags {
		md := &panel.MdnsNode{Domain: []string{"t.example.com"}}
		md.ServerPort = freeUDPPort(t)
		info := &panel.NodeInfo{Type: "mdns", Mdns: md, Common: &md.CommonNode}
		if err := m.AddNode(tag, info, nil); err != nil {
			t.Fatalf("AddNode %s: %v", tag, err)
		}
		if _, err := m.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// 🔴 The same subscriber on two nodes, removed from one: their traffic on the
// other must still be billed. The uuid -> id map was shared by all nodes, so
// the removal made them an "unknown user" everywhere.
func TestMdns_RemovalFromOneNodeKeepsTheOther(t *testing.T) {
	u := panel.UserInfo{Id: 9, Uuid: "u9"}
	m := mdnsWithNodes(t, []panel.UserInfo{u}, "A", "B")
	if err := m.DelUsers([]panel.UserInfo{u}, "A", nil); err != nil {
		t.Fatal(err)
	}
	// Traffic counted for the user on B (injected where DelNode would carry it).
	m.carried["B"] = map[string][2]int64{u.Uuid: {100, 200}}
	got, err := m.GetUserTrafficSlice("B", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].UID != 9 || got[0].Upload != 100 || got[0].Download != 200 {
		t.Fatalf("traffic on node B = %+v, want UID 9 with 100/200", got)
	}
	if devs := onlineUsers(map[string][]string{u.Uuid: {"5.1.1.1"}}, m.users["A"]); len(devs) != 0 {
		t.Fatalf("user still resolved on the node they left: %+v", devs)
	}
}

// What a node counted before a reload is reported after it, once the user is
// back on the node - not dropped with the old tunnel.
func TestMdns_ReloadCarriesTrafficToTheNextReport(t *testing.T) {
	u := panel.UserInfo{Id: 3, Uuid: "u3"}
	m := mdnsWithNodes(t, []panel.UserInfo{u}, "A")
	if err := m.DelNode("A"); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.carried["A"] = map[string][2]int64{u.Uuid: {10, 20}}
	m.mu.Unlock()
	if got, _ := m.GetUserTrafficSlice("A", true); len(got) != 0 {
		t.Fatalf("report while the node is down = %+v, want nothing yet", got)
	}
	md := &panel.MdnsNode{Domain: []string{"t.example.com"}}
	md.ServerPort = freeUDPPort(t)
	if err := m.AddNode("A", &panel.NodeInfo{Type: "mdns", Mdns: md, Common: &md.CommonNode}, nil); err != nil {
		t.Fatal(err)
	}
	// The node is back but its users are not yet: the bytes must wait.
	m.mu.Lock()
	delete(m.users, "A")
	m.mu.Unlock()
	if got, _ := m.GetUserTrafficSlice("A", true); len(got) != 0 {
		t.Fatalf("report before users are re-added = %+v, want nothing yet", got)
	}
	_, _ = m.AddUsers(&vCore.AddUsersParams{Tag: "A", Users: []panel.UserInfo{u}})
	got, _ := m.GetUserTrafficSlice("A", true)
	if len(got) != 1 || got[0].UID != 3 || got[0].Upload != 10 || got[0].Download != 20 {
		t.Fatalf("after the reload the report is %+v, want UID 3 with 10/20", got)
	}
	if got, _ := m.GetUserTrafficSlice("A", true); len(got) != 0 {
		t.Fatalf("carried traffic reported twice: %+v", got)
	}
}
