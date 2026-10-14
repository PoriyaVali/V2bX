package mdns

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/miekg/dns"
)

func TestMdnsHonorsConfiguredListenIP(t *testing.T) {
	// Another service owns this port on 127.0.0.1. The MDNS node has the
	// same port on a different configured address and must still answer.
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	port := other.LocalAddr().(*net.UDPAddr).Port
	c, _ := New(nil)
	m := c.(*Mdns)
	defer m.Close()
	md := &panel.MdnsNode{Domain: []string{"t.example.com"}}
	md.ServerPort = port
	info := &panel.NodeInfo{Type: "mdns", Mdns: md, Common: &md.CommonNode}
	if err := m.AddNode("specific-address", info, &conf.Options{ListenIP: "127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("t.example.com.", dns.TypeA)
	client := &dns.Client{Timeout: 100 * time.Millisecond}
	address := net.JoinHostPort("127.0.0.2", strconv.Itoa(port))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		answer, _, err := client.Exchange(q, address)
		if err == nil && answer.Response && answer.Id == q.Id {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("MDNS did not answer on the configured IP while the same port was occupied on another address")
}
