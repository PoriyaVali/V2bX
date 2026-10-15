//go:build with_quic

package sing

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/sagernet/quic-go/http3"
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

// An HTTP/3 request that does not authenticate is how a prober tells a
// Hysteria2 server apart: sing-box answered it with a bare 404 on every path.
// With no masquerade configured, the node's decoy site answers instead.
func TestSing_Hysteria2ProberSeesDecoySite(t *testing.T) {
	b, _ := startSing(t)
	hy := &panel.Hysteria2Node{}
	hy.ServerPort = freeUDPPort(t)
	info := &panel.NodeInfo{Type: "hysteria2", Security: panel.Tls, Hysteria2: hy, Common: &hy.CommonNode}
	if err := b.AddNode("hy2-decoy", info, tlsNodeOptions(t)); err != nil {
		t.Fatal(err)
	}
	rt := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "node.test", NextProtos: []string{http3.NextProtoH3}}}
	defer rt.Close()
	client := &http.Client{Transport: rt, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(hy.ServerPort)) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assertDecoyPage(t, resp, string(body))
}
