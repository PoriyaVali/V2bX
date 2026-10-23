package xray

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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
	"github.com/PoriyaVali/V2bX/common/decoy"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

// skipUnderXrayCertReloadRace skips a test that serves TLS from certificate
// files when the race detector is on. xray-core's hot reload of those files
// (transport/internet/tls/config.go, setupOcspTicker) rewrites the served
// certificate without a lock - once at start, then hourly - while handshakes
// read it. That is xray's own race, present on every xray TLS node; it is not
// in the code these tests are about.
func skipUnderXrayCertReloadRace(t *testing.T) {
	t.Helper()
	if raceDetector {
		t.Skip("xray-core's certificate hot reload races the first TLS handshakes; see skipUnderXrayCertReloadRace")
	}
}

// certFiles writes a throwaway certificate for a TLS node under test.
func certFiles(t *testing.T) *conf.CertConfig {
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
	keyDER, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	cert, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &conf.CertConfig{CertMode: "file", CertFile: cert, KeyFile: kf}
}

// tlsXrayNode runs a real xray core with one TLS node of the given panel type.
func tlsXrayNode(t *testing.T, info *panel.NodeInfo, xo *conf.XrayOptions, users ...panel.UserInfo) (*Xray, string) {
	t.Helper()
	return tlsXrayNodeWithCover(t, info, xo, nil, users...)
}

func tlsXrayNodeWithCover(t *testing.T, info *panel.NodeInfo, xo *conf.XrayOptions, cover *decoy.Config, users ...panel.UserInfo) (*Xray, string) {
	t.Helper()
	limiter.Init()
	tag := "decoy-" + info.Type
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: conf.NewXrayConfig()})
	if err != nil {
		t.Fatal(err)
	}
	x := c.(*Xray)
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })
	if err := x.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", XrayOptions: xo, CertConfig: certFiles(t), Decoy: cover}); err != nil {
		t.Fatal(err)
	}
	return x, tag
}

// probeHTTP1 completes the node's TLS handshake offering only HTTP/1.1 and
// sends an ordinary browser request.
func probeHTTP1(t *testing.T, port int) (*http.Response, string) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true, ServerName: "node.test", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
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

// probeHTTP2 is a browser that negotiates h2, which xray's TLS offers first.
func probeHTTP2(t *testing.T, port int) (*http.Response, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: "node.test", NextProtos: []string{"h2"}},
	}}
	resp, err := client.Get("https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/")
	if err != nil {
		t.Fatalf("an h2 prober got no answer: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func isDecoyPage(resp *http.Response, body string) bool {
	return resp.StatusCode == http.StatusOK && resp.Header.Get("Server") == "" && strings.Contains(body, "<title>")
}

// A prober that completes the TLS handshake of a VLESS or Trojan node and then
// sends an ordinary request got the connection closed - the tell of a proxy.
// Over HTTP/1.1 and HTTP/2 alike it now gets the node's decoy site.
func TestXray_TLSProberSeesDecoySite(t *testing.T) {
	skipUnderXrayCertReloadRace(t)
	trojan := &panel.TrojanNode{Network: "tcp"}
	vless := &panel.VAllssNode{Network: "tcp"}
	for _, info := range []*panel.NodeInfo{
		{Type: "trojan", Security: panel.Tls, Trojan: trojan, Common: &trojan.CommonNode},
		{Type: "vless", Security: panel.Tls, VAllss: vless, Common: &vless.CommonNode},
	} {
		info.Common.ServerPort = freePort(t)
		x, tag := tlsXrayNode(t, info, conf.NewXrayOptions())
		if resp, body := probeHTTP1(t, info.Common.ServerPort); !isDecoyPage(resp, body) {
			t.Errorf("%s over HTTP/1.1: %s, Server %q, body %.60q", info.Type, resp.Status, resp.Header.Get("Server"), body)
		}
		resp, body := probeHTTP2(t, info.Common.ServerPort)
		if !isDecoyPage(resp, body) || resp.ProtoMajor != 2 {
			t.Errorf("%s over HTTP/2: %s %s, Server %q, body %.60q", info.Type, resp.Proto, resp.Status, resp.Header.Get("Server"), body)
		}

		x.decoysMu.Lock()
		d := x.decoys[tag]
		x.decoysMu.Unlock()
		if d == nil {
			t.Fatalf("%s: no decoy recorded", info.Type)
		}
		if err := x.DelNode(tag); err != nil {
			t.Fatal(err)
		}
		if c, err := net.DialTimeout("tcp", d.Addr(), time.Second); err == nil {
			c.Close()
			t.Fatalf("%s: the decoy site outlived its node", info.Type)
		}
	}
}

// Where xray cannot fall back, or the operator chose otherwise, nothing is
// attached and nothing is started.
func TestWantsDecoy(t *testing.T) {
	tlsCert := &conf.CertConfig{CertMode: "file"}
	vless := func(network, encryption string) *panel.NodeInfo {
		v := &panel.VAllssNode{Network: network, Encryption: encryption}
		return &panel.NodeInfo{Type: "vless", Security: panel.Tls, VAllss: v, Common: &v.CommonNode}
	}
	trojanWS := &panel.TrojanNode{Network: "ws"}
	off := false
	cases := []struct {
		name string
		info *panel.NodeInfo
		opt  *conf.Options
		want bool
	}{
		{"vless tcp tls", vless("tcp", ""), &conf.Options{XrayOptions: conf.NewXrayOptions(), CertConfig: tlsCert}, true},
		{"vless with decryption", vless("tcp", "mlkem768x25519plus"), &conf.Options{XrayOptions: conf.NewXrayOptions(), CertConfig: tlsCert}, false},
		{"vless ws", vless("ws", ""), &conf.Options{XrayOptions: conf.NewXrayOptions(), CertConfig: tlsCert}, false},
		{"no certificate", vless("tcp", ""), &conf.Options{XrayOptions: conf.NewXrayOptions(), CertConfig: &conf.CertConfig{CertMode: "none"}}, false},
		{"operator fallbacks", vless("tcp", ""), &conf.Options{XrayOptions: &conf.XrayOptions{EnableFallback: true}, CertConfig: tlsCert}, false},
		{"DecoySite false", vless("tcp", ""), &conf.Options{XrayOptions: &conf.XrayOptions{DecoySite: &off}, CertConfig: tlsCert}, false},
		{"trojan ws", &panel.NodeInfo{Type: "trojan", Security: panel.Tls, Trojan: trojanWS, Common: &trojanWS.CommonNode},
			&conf.Options{XrayOptions: conf.NewXrayOptions(), CertConfig: tlsCert}, false},
	}
	for _, c := range cases {
		if got := wantsDecoy(c.opt, c.info); got != c.want {
			t.Errorf("%s: wantsDecoy = %v, want %v", c.name, got, c.want)
		}
	}
	reality := vless("tcp", "")
	reality.Security = panel.Reality
	if wantsDecoy(&conf.Options{XrayOptions: conf.NewXrayOptions(), CertConfig: tlsCert}, reality) {
		t.Error("REALITY relays strangers to the borrowed site; it must not get a decoy")
	}
}

// The decoy only meets strangers: a subscriber on the same VLESS TLS node is
// carried as before.
func TestXray_DecoyNodeStillCarriesUsers(t *testing.T) {
	skipUnderXrayCertReloadRace(t)
	v := &panel.VAllssNode{Network: "tcp"}
	v.ServerPort = freePort(t)
	info := &panel.NodeInfo{Type: "vless", Security: panel.Tls, VAllss: v, Common: &v.CommonNode}
	xo := conf.NewXrayOptions()
	xo.DisableSniffing = true
	users := []panel.UserInfo{{Id: 1, Uuid: e2eUUID}}
	x, tag := tlsXrayNodeWithCover(t, info, xo, &decoy.Config{RequestsPerSecond: 1}, users...)
	if _, err := x.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	if err := x.removeOutbound(tag); err != nil {
		t.Fatal(err)
	}
	settings := json.RawMessage(`{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`)
	ob, err := (&coreConf.OutboundDetourConfig{Protocol: "freedom", Tag: tag, Settings: &settings}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := x.addOutbound(ob); err != nil {
		t.Fatal(err)
	}
	// Exhaust the cover site's budget. A valid subscriber on the same port
	// must still pass protocol authentication and reach the destination.
	x.decoysMu.Lock()
	site := x.decoys[tag]
	x.decoysMu.Unlock()
	overloaded := false
	for i := 0; i < 1024; i++ {
		r, err := http.Get(site.URL())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode == http.StatusServiceUnavailable {
			overloaded = true
			break
		}
	}
	if !overloaded {
		t.Fatal("could not exercise the public request budget")
	}

	echo := echoServer(t)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(v.ServerPort)),
		&tls.Config{InsecureSkipVerify: true, ServerName: "node.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	id, _ := uuid.ParseString(e2eUUID)
	host, portStr, _ := net.SplitHostPort(echo)
	port, _ := strconv.Atoi(portStr)
	req := &protocol.RequestHeader{
		Command: protocol.RequestCommandTCP,
		Address: xnet.ParseAddress(host),
		Port:    xnet.Port(port),
		User:    &protocol.MemoryUser{Account: &vless.MemoryAccount{ID: protocol.NewID(id)}},
	}
	if err := encoding.EncodeRequestHeader(conn, req, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, err := encoding.DecodeResponseHeader(conn, req); err != nil {
		t.Fatalf("subscriber refused on a decoy node: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("subscriber traffic not carried: %q, %v", buf, err)
	}
}
