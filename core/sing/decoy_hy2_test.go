//go:build with_quic

package sing

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
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

func freeTCPUDPPort(t *testing.T) int {
	t.Helper()
	// A free UDP port can already have an unrelated TCP listener/connection.
	// These cover tests need both transports on the same port. Let TCP choose
	// an available port, then check UDP while TCP is still reserved.
	for attempt := 0; attempt < 100; attempt++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err != nil {
			tcp.Close()
			continue
		}
		udp.Close()
		tcp.Close()
		return port
	}
	t.Fatal("could not find a shared TCP/UDP test port")
	return 0
}

// An HTTP/3 request that does not authenticate is how a prober tells a
// Hysteria2 server apart: sing-box answered it with a bare 404 on every path.
// With no masquerade configured, the node's decoy site answers instead.
func TestSing_Hysteria2ProberSeesDecoySite(t *testing.T) {
	b, _ := startSing(t)
	hy := &panel.Hysteria2Node{}
	hy.ServerPort = freeTCPUDPPort(t)
	info := &panel.NodeInfo{Type: "hysteria2", Security: panel.Tls, Hysteria2: hy, Common: &hy.CommonNode}
	options := tlsNodeOptions(t)
	if err := b.AddNode("hy2-decoy", info, options); err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(options.CertConfig.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("could not trust test certificate")
	}
	rt := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "node.test", NextProtos: []string{http3.NextProtoH3}}}
	defer rt.Close()
	client := &http.Client{Transport: rt, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(hy.ServerPort)) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assertDecoyPage(t, resp, string(body))
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "node.test"}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	tcp := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	tcpResponse, err := tcp.Get("https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(hy.ServerPort)) + "/")
	if err != nil {
		t.Fatal(err)
	}
	tcpBody, _ := io.ReadAll(tcpResponse.Body)
	tcpResponse.Body.Close()
	if tcpResponse.ProtoMajor != 2 || string(tcpBody) != string(body) {
		t.Fatal("TCP HTTPS and QUIC showed different sites")
	}
	if err := b.DelNode("hy2-decoy"); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hy.ServerPort)), 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("TCP cover outlived UDP node")
	}
}

func TestSing_TUICHasOwnedHTTPSCompanion(t *testing.T) {
	b, _ := startSing(t)
	tuic := &panel.TuicNode{}
	tuic.ServerPort = freeTCPUDPPort(t)
	info := &panel.NodeInfo{Type: "tuic", Security: panel.Tls, Tuic: tuic, Common: &tuic.CommonNode}
	options := tlsNodeOptions(t)
	if err := b.AddNode("tuic-cover", info, options); err != nil {
		t.Fatal(err)
	}
	cert, _ := os.ReadFile(options.CertConfig.CertFile)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "node.test"}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(tuic.ServerPort))
	r, err := client.Get("https://" + address + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	assertDecoyPage(t, r, string(body))
	if err := b.DelNode("tuic-cover"); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("TUIC companion outlived node")
	}
}
