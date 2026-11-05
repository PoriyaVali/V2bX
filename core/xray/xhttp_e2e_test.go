package xray

// VLESS over XHTTP, with REALITY and with TLS, the way Irboard configures it:
// the node is built by this core from the panel's network_settings, and it is
// dialled by both client families Irboard serves it to. Xray-based clients get
// the whole xhttpSettings from a share link, "extra" included. mihomo-based
// clients get the Clash Meta profile's xhttp-opts.

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const xhttpTestHost = "xhttp.test"

type xhttpTestNode struct {
	port     int
	echo     string
	security int
	// REALITY
	publicKey []byte
	shortID   string
	// TLS: the node's leaf, pinned by the Xray client.
	certSHA256 string
}

// xhttpNode runs this core with one VLESS node over XHTTP, its
// network_settings exactly as the panel stores them, and one user.
func xhttpNode(t *testing.T, security int, networkSettings string) xhttpTestNode {
	t.Helper()
	n, err := startXHTTPNode(t, security, networkSettings)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// startXHTTPNode is xhttpNode, returning the error AddNode gave the panel's
// network_settings instead of failing the test.
func startXHTTPNode(t *testing.T, security int, networkSettings string) (xhttpTestNode, error) {
	t.Helper()
	limiter.Init()
	tag := fmt.Sprintf("e2e-xhttp-%d", security)
	users := []panel.UserInfo{{Id: 1, Uuid: e2eUUID}}
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

	n := xhttpTestNode{port: freePort(t), echo: echoServer(t), security: security}
	v := &panel.VAllssNode{Network: "xhttp", NetworkSettings: json.RawMessage(networkSettings), Tls: security}
	v.ServerPort = n.port
	opts := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
	opts.XrayOptions.DisableSniffing = true
	switch security {
	case panel.Reality:
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			t.Fatal(err)
		}
		key, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		n.publicKey, n.shortID = key.PublicKey().Bytes(), "0123abcd"
		siteHost, sitePort, _ := net.SplitHostPort(tls13Site(t))
		v.TlsSettings = panel.TlsSettings{
			ServerName: realityTestSNI, Dest: siteHost, ServerPort: sitePort,
			ShortId: n.shortID, PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
		}
	case panel.Tls:
		certFile, keyFile, sum := xhttpCertificate(t)
		n.certSHA256 = sum
		opts.CertConfig = &conf.CertConfig{CertMode: "file", CertDomain: xhttpTestHost, CertFile: certFile, KeyFile: keyFile}
	}
	info := &panel.NodeInfo{Type: "vless", Security: security, VAllss: v, Common: &v.CommonNode}
	if err := x.AddNode(tag, info, opts); err != nil {
		return n, err
	}
	if _, err := x.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	// The echo server is on loopback, which the node's own outbound refuses.
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
	return n, nil
}

// xhttpCertificate writes a certificate for xhttpTestHost, as the file mode of
// a TLS node reads it, and returns its paths and the leaf's SHA-256.
func xhttpCertificate(t *testing.T) (string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: xhttpTestHost},
		DNSNames: []string{xhttpTestHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return certFile, keyFile, hex.EncodeToString(sum[:])
}

// echoThrough writes through conn to the echo server and wants it back.
func echoThrough(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return fmt.Errorf("echoed %q", buf)
	}
	return nil
}

// xrayXHTTP dials the node as an Xray-based client does from a share link:
// xhttpSettings is what the link's path, host, mode and extra parameters give.
func xrayXHTTP(t *testing.T, n xhttpTestNode, xhttpSettings string) error {
	t.Helper()
	var security string
	switch n.security {
	case panel.Reality:
		security = fmt.Sprintf(`"security":"reality","realitySettings":{"serverName":%q,"fingerprint":"chrome","password":%q,"shortId":%q,"spiderX":"/"}`,
			realityTestSNI, base64.RawURLEncoding.EncodeToString(n.publicKey), n.shortID)
	case panel.Tls:
		security = fmt.Sprintf(`"security":"tls","tlsSettings":{"serverName":%q,"fingerprint":"chrome","pinnedPeerCertSha256":%q}`,
			xhttpTestHost, n.certSHA256)
	}
	raw := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"encryption":"none"}]}]},"streamSettings":{"network":"xhttp",%s,"xhttpSettings":%s}}]}`,
		n.port, e2eUUID, security, xhttpSettings)
	var cfg coreConf.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("client config: %w", err)
	}
	pb, err := cfg.Build()
	if err != nil {
		return fmt.Errorf("client config: %w", err)
	}
	inst, err := core.New(pb)
	if err != nil {
		return err
	}
	if err := inst.Start(); err != nil {
		return err
	}
	defer inst.Close()
	host, port, _ := net.SplitHostPort(n.echo)
	p, _ := strconv.Atoi(port)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, inst, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(p)))
	if err != nil {
		return err
	}
	defer conn.Close()
	return echoThrough(conn)
}

// mihomoXHTTP dials the node as a mihomo-based client does from a Clash Meta
// profile: xhttpOpts is the profile's xhttp-opts, read by mihomo itself.
func mihomoXHTTP(t *testing.T, n xhttpTestNode, xhttpOpts map[string]any) error {
	t.Helper()
	proxy := map[string]any{
		"name": "xhttp", "type": "vless", "server": "127.0.0.1", "port": n.port, "uuid": e2eUUID,
		"tls": true, "client-fingerprint": "chrome", "network": "xhttp", "xhttp-opts": xhttpOpts,
	}
	switch n.security {
	case panel.Reality:
		proxy["servername"] = realityTestSNI
		proxy["reality-opts"] = map[string]any{"public-key": base64.RawURLEncoding.EncodeToString(n.publicKey), "short-id": n.shortID}
	case panel.Tls:
		proxy["servername"], proxy["skip-cert-verify"] = xhttpTestHost, true
	}
	raw, err := json.Marshal(proxy)
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(profile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(mihomoClient(t), profile, n.echo).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

var (
	mihomoClientOnce sync.Once
	mihomoClientDir  string
	mihomoClientPath string
	mihomoClientErr  error
)

// TestMain removes the mihomo client the tests built.
func TestMain(m *testing.M) {
	code := m.Run()
	if mihomoClientDir != "" {
		_ = os.RemoveAll(mihomoClientDir)
	}
	os.Exit(code)
}

// mihomoClient builds testdata/mihomoclient once per test binary.
func mihomoClient(t *testing.T) string {
	t.Helper()
	mihomoClientOnce.Do(func() {
		dir, err := os.MkdirTemp("", "v2bx-mihomoclient-")
		if err != nil {
			mihomoClientErr = err
			return
		}
		mihomoClientDir = dir
		mihomoClientPath = filepath.Join(dir, "mihomoclient")
		out, err := exec.Command("go", "build", "-o", mihomoClientPath, "./testdata/mihomoclient").CombinedOutput()
		if err != nil {
			mihomoClientErr = fmt.Errorf("build the mihomo client: %v\n%s", err, out)
		}
	})
	if mihomoClientErr != nil {
		t.Fatal(mihomoClientErr)
	}
	return mihomoClientPath
}

// Every XHTTP mode, over REALITY and over TLS, for both client families.
func TestXHTTPModesOverRealityAndTLS(t *testing.T) {
	for _, security := range []int{panel.Reality, panel.Tls} {
		for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
			name := map[int]string{panel.Reality: "reality", panel.Tls: "tls"}[security] + "/" + mode
			t.Run(name, func(t *testing.T) {
				settings := fmt.Sprintf(`{"path":"/xh","host":"","mode":%q}`, mode)
				n := xhttpNode(t, security, settings)
				if err := xrayXHTTP(t, n, settings); err != nil {
					t.Errorf("xray client: %v", err)
				}
				if err := mihomoXHTTP(t, n, map[string]any{"path": "/xh", "mode": mode}); err != nil {
					t.Errorf("mihomo client: %v", err)
				}
			})
		}
	}
}

// Settings shaped as a PHP panel sends them: Irboard's default template's
// {"extra":{}} arrives as "extra":[], and so does an emptied map. Xray refused
// the node, so it never came up.
func TestXHTTPSettingsAsPanelsSendThem(t *testing.T) {
	for _, tc := range []struct{ name, settings string }{
		{"empty extra", `{"path":"/xh","host":"","mode":"auto","extra":[]}`},
		{"empty maps in extra", `{"path":"/xh","host":"","mode":"auto","extra":{"headers":[],"xmux":[],"downloadSettings":[]}}`},
		{"empty maps without extra", `{"path":"/xh","host":"","mode":"auto","headers":[],"xmux":[]}`},
		{"extra as an object", `{"path":"/xh","host":"","mode":"auto","extra":{}}`},
		{"extra null", `{"path":"/xh","host":"","mode":"auto","extra":null}`},
	} {
		for _, security := range []int{panel.Reality, panel.Tls} {
			t.Run(map[int]string{panel.Reality: "reality", panel.Tls: "tls"}[security]+"/"+tc.name, func(t *testing.T) {
				n, err := startXHTTPNode(t, security, tc.settings)
				if err != nil {
					t.Fatalf("the node did not start: %v", err)
				}
				if err := xrayXHTTP(t, n, `{"path":"/xh","mode":"auto"}`); err != nil {
					t.Errorf("xray client: %v", err)
				}
				if err := mihomoXHTTP(t, n, map[string]any{"path": "/xh", "mode": "auto"}); err != nil {
					t.Errorf("mihomo client: %v", err)
				}
			})
		}
	}
	// The whole of the settings, emptied.
	n, err := startXHTTPNode(t, panel.Reality, `[]`)
	if err != nil {
		t.Fatalf("[] settings: the node did not start: %v", err)
	}
	if err := xrayXHTTP(t, n, `{"mode":"auto"}`); err != nil {
		t.Errorf("[] settings: xray client: %v", err)
	}
}

// What the node's extra configures, a client must do too, or be refused: the
// padding's range, placement and method, the uplink's method, where the
// session id, the sequence number and the uplink data go. Xray-based clients
// get extra from the share link. mihomo-based clients got only path, host and
// mode, so every one of them was refused; Irboard now maps extra into
// xhttp-opts, as given here (app/Utils/Xhttp.php).
func TestXHTTPClientsMustMatchTheNodesExtra(t *testing.T) {
	for _, tc := range []struct {
		name     string
		security int
		mode     string
		extra    string
		mihomo   map[string]any
	}{{
		name: "reality/padding", security: panel.Reality, mode: "auto",
		extra: `{"xPaddingBytes":"1200-1500","xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingHeader":"X-Pad","xPaddingMethod":"tokenish"}`,
		mihomo: map[string]any{"x-padding-bytes": "1200-1500", "x-padding-obfs-mode": true, "x-padding-placement": "header",
			"x-padding-header": "X-Pad", "x-padding-method": "tokenish"},
	}, {
		name: "tls/placements", security: panel.Tls, mode: "packet-up",
		extra: `{"xPaddingBytes":"300-600","uplinkHTTPMethod":"PUT","sessionIDPlacement":"header","sessionIDKey":"X-Sid","seqPlacement":"query","seqKey":"s","uplinkDataPlacement":"header","uplinkDataKey":"X-Up","scMaxEachPostBytes":"8000"}`,
		mihomo: map[string]any{"x-padding-bytes": "300-600", "uplink-http-method": "PUT", "session-placement": "header", "session-key": "X-Sid",
			"seq-placement": "query", "seq-key": "s", "uplink-data-placement": "header", "uplink-data-key": "X-Up", "sc-max-each-post-bytes": "8000"},
	}, {
		name: "reality/stream-up with client-only options", security: panel.Reality, mode: "stream-up",
		extra: `{"xPaddingBytes":"50-90","headers":{"X-Client":"irboard"},"xmux":{"maxConcurrency":"4-8","hKeepAlivePeriod":30},"noGRPCHeader":true}`,
		mihomo: map[string]any{"x-padding-bytes": "50-90", "headers": map[string]string{"X-Client": "irboard"}, "no-grpc-header": true,
			"reuse-settings": map[string]any{"max-concurrency": "4-8", "h-keep-alive-period": 30}},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			settings := fmt.Sprintf(`{"path":"/xh","host":"","mode":%q,"extra":%s}`, tc.mode, tc.extra)
			n := xhttpNode(t, tc.security, settings)
			// A share link's path, mode and extra.
			if err := xrayXHTTP(t, n, settings); err != nil {
				t.Errorf("xray client with the link's extra: %v", err)
			}
			if err := xrayXHTTP(t, n, fmt.Sprintf(`{"path":"/xh","mode":%q}`, tc.mode)); err == nil {
				t.Error("an xray client without extra was let in: the case tests nothing")
			}
			opts := map[string]any{"path": "/xh", "mode": tc.mode}
			if err := mihomoXHTTP(t, n, opts); err == nil {
				t.Error("a mihomo client without the mapped options was let in: the case tests nothing")
			}
			for k, v := range tc.mihomo {
				opts[k] = v
			}
			if err := mihomoXHTTP(t, n, opts); err != nil {
				t.Errorf("mihomo client with extra mapped into xhttp-opts: %v", err)
			}
		})
	}
}
