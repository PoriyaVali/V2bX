package sing

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/sagernet/sing-box/option"
)

// decoyTestCert writes a throwaway certificate for a TLS node under test.
func decoyTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "node.test"},
		DNSNames:     []string{"node.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// tlsNodeOptions are the options of a TLS node on loopback with a throwaway
// certificate.
func tlsNodeOptions(t *testing.T) *conf.Options {
	t.Helper()
	cert, key := decoyTestCert(t)
	return &conf.Options{
		ListenIP:    "127.0.0.1",
		SingOptions: conf.NewSingOptions(),
		CertConfig:  &conf.CertConfig{CertMode: "file", CertFile: cert, KeyFile: key},
	}
}

// probeHTTP plays an active prober: complete the TLS handshake, send an
// ordinary browser request, read what comes back.
func probeHTTP(t *testing.T, port int) (*http.Response, string) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true, ServerName: "node.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET / HTTP/1.1\r\nHost: node.test\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
		"Accept: text/html,application/xhtml+xml\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("a prober got no HTTP answer: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func assertDecoyPage(t *testing.T, resp *http.Response, body string) {
	t.Helper()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Server") != "nginx" || !strings.Contains(body, "<title>") {
		t.Fatalf("prober got %s, Server %q, body %.80q - not the decoy site", resp.Status, resp.Header.Get("Server"), body)
	}
}

// An anytls node answers a prober that spoke TLS and then sent no valid
// password with its decoy site - through the shared decoy package, which the
// xray core and hysteria2 masquerades use too - and retires the site with the
// node.
func TestSing_AnyTLSProberSeesDecoySite(t *testing.T) {
	b, _ := startSing(t)
	at := &panel.AnyTlsNode{}
	at.ServerPort = freeTCPPort(t)
	info := &panel.NodeInfo{Type: "anytls", Security: panel.Tls, AnyTls: at, Common: &at.CommonNode}
	if err := b.AddNode("anytls-decoy", info, tlsNodeOptions(t)); err != nil {
		t.Fatal(err)
	}
	resp, body := probeHTTP(t, at.ServerPort)
	assertDecoyPage(t, resp, body)

	b.decoysMu.Lock()
	d := b.decoys["anytls-decoy"]
	b.decoysMu.Unlock()
	if d == nil {
		t.Fatal("no decoy recorded for the node")
	}
	if err := b.DelNode("anytls-decoy"); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", d.Addr(), time.Second); err == nil {
		c.Close()
		t.Fatal("the decoy site outlived its node")
	}
}

// Only inbounds whose unauthenticated connections can actually reach the site
// get one; an operator's own masquerade or fallback wins. Trojan is refused
// because sing-box routes its fallback through the private-destination rules,
// which reject loopback.
func TestWantsDecoy(t *testing.T) {
	tlsOn := &option.InboundTLSOptions{Enabled: true}
	trojan := func(o option.TrojanInboundOptions) option.Inbound {
		return option.Inbound{Type: "trojan", Options: &o}
	}
	cases := []struct {
		name string
		in   option.Inbound
		want bool
	}{
		{"anytls", option.Inbound{Options: &option.AnyTLSInboundOptions{}}, true},
		{"anytls with a fallback", option.Inbound{Options: &option.AnyTLSInboundOptions{Fallback: &option.ServerOptions{Server: "127.0.0.1", ServerPort: 80}}}, false},
		{"trojan", trojan(option.TrojanInboundOptions{InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: tlsOn}}), false},
		{"hysteria2", option.Inbound{Options: &option.Hysteria2InboundOptions{}}, true},
		{"hysteria2 with masquerade", option.Inbound{Options: &option.Hysteria2InboundOptions{Masquerade: &option.Hysteria2Masquerade{Type: "string"}}}, false},
		{"vless", option.Inbound{Options: &option.VLESSInboundOptions{}}, false},
	}
	for _, c := range cases {
		if got := wantsDecoy(c.in); got != c.want {
			t.Errorf("%s: wantsDecoy = %v, want %v", c.name, got, c.want)
		}
	}
}

// DecoySite: false keeps a node closing on strangers, as before.
func TestSing_DecoySiteOffStartsNoSite(t *testing.T) {
	b, _ := startSing(t)
	at := &panel.AnyTlsNode{}
	at.ServerPort = freeTCPPort(t)
	info := &panel.NodeInfo{Type: "anytls", Security: panel.Tls, AnyTls: at, Common: &at.CommonNode}
	opts := tlsNodeOptions(t)
	off := false
	opts.SingOptions.DecoySite = &off
	if err := b.AddNode("anytls-nodecoy", info, opts); err != nil {
		t.Fatal(err)
	}
	b.decoysMu.Lock()
	d := b.decoys["anytls-nodecoy"]
	b.decoysMu.Unlock()
	if d != nil {
		t.Fatal("a decoy started although DecoySite is false")
	}
}

// TUIC sends with bbr unless the panel chose an algorithm; sing-box alone
// would use cubic, which halves its rate at every radio loss.
func TestTUICDefaultsToBBR(t *testing.T) {
	for panelValue, want := range map[string]string{"": "bbr", "cubic": "cubic", "new_reno": "new_reno", "bbr": "bbr"} {
		tuic := &panel.TuicNode{CongestionControl: panelValue}
		info := &panel.NodeInfo{Type: "tuic", Security: panel.Tls, Tuic: tuic, Common: &tuic.CommonNode}
		in, err := getInboundOptions("t", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions(), CertConfig: conf.NewCertConfig()})
		if err != nil {
			t.Fatal(err)
		}
		if got := in.Options.(*option.TUICInboundOptions).CongestionControl; got != want {
			t.Errorf("panel %q: congestion control %q, want %q", panelValue, got, want)
		}
	}
}
