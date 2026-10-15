package xray

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
)

const realityTestSNI = "reality.test"

// tls13Site stands in for the site a REALITY node borrows: an ordinary TLS 1.3
// server the node relays unauthenticated handshakes to.
func tls13Site(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: realityTestSNI},
		DNSNames:     []string{realityTestSNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

type realityTestNode struct {
	port      int
	publicKey []byte
	shortID   string
	echo      string
}

// realityNode runs a real xray core with one VLESS+REALITY node built from
// panel data the way production builds it, one user, and an echo server the
// node may reach.
func realityNode(t *testing.T) realityTestNode {
	t.Helper()
	limiter.Init()
	const tag = "e2e-reality"
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

	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	siteHost, sitePort, _ := net.SplitHostPort(tls13Site(t))
	node := realityTestNode{
		port:      freePort(t),
		publicKey: key.PublicKey().Bytes(),
		shortID:   "0123abcd",
		echo:      echoServer(t),
	}
	v := &panel.VAllssNode{
		Network: "tcp",
		Tls:     panel.Reality,
		TlsSettings: panel.TlsSettings{
			ServerName: realityTestSNI,
			Dest:       siteHost,
			ServerPort: sitePort,
			ShortId:    node.shortID,
			PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
		},
	}
	v.ServerPort = node.port
	info := &panel.NodeInfo{Type: "vless", Security: panel.Reality, VAllss: v, Common: &v.CommonNode}
	xo := conf.NewXrayOptions()
	xo.DisableSniffing = true
	if err := x.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", XrayOptions: xo}); err != nil {
		t.Fatal(err)
	}
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
	return node
}

// realityVLESS dials the node with a REALITY ClientHello shaped by fingerprint,
// sends one VLESS request to the echo server and checks the reply. It returns
// the first thing that went wrong.
func realityVLESS(n realityTestNode, fingerprint string) error {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(n.port)), 3*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	shortID, _ := hex.DecodeString(n.shortID)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := reality.UClient(raw, &reality.Config{
		ServerName:  realityTestSNI,
		Fingerprint: fingerprint,
		PublicKey:   n.publicKey,
		ShortId:     shortID,
		SpiderX:     "/",
		// UClient reads ten values from SpiderY when the server does not
		// authenticate it; a nil slice would panic instead of reporting that.
		SpiderY: make([]int64, 10),
	}, ctx, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(n.port)))
	if err != nil {
		return err
	}
	id, err := uuid.ParseString(e2eUUID)
	if err != nil {
		return err
	}
	echoHost, echoPort, _ := net.SplitHostPort(n.echo)
	port, _ := strconv.Atoi(echoPort)
	req := &protocol.RequestHeader{
		Version: 0,
		Command: protocol.RequestCommandTCP,
		Address: xnet.ParseAddress(echoHost),
		Port:    xnet.Port(port),
		User:    &protocol.MemoryUser{Account: &vless.MemoryAccount{ID: protocol.NewID(id)}},
	}
	if err := encoding.EncodeRequestHeader(conn, req, &encoding.Addons{}); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	if _, err := encoding.DecodeResponseHeader(conn, req); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// 🔴 A REALITY node on the xray core must authenticate a ClientHello that
// carries only an X25519 key share.
//
// xtls/reality 8cdf7bf9 (shipped with Xray 26.9.8/26.9.9) started refusing
// every ClientHello without an X25519MLKEM768 share, and refusing means the
// node quietly relays the user to the borrowed site: the client reports
// "reality verification failed", the node logs nothing. mihomo sends that
// share only when a profile opts in (reality-opts.support-x25519mlkem768),
// and sing-box's clients (Hiddify, NekoBox, Karing, sing-box itself) never
// send it - so after the core update those users could not connect to any
// VLESS REALITY node on xray, while anytls nodes (sing-box's own REALITY)
// kept working. Both shapes must work.
func TestRealityAcceptsClientsWithAndWithoutMLKEM(t *testing.T) {
	n := realityNode(t)
	for _, fp := range []string{
		"hellosafari_16_0", // X25519 only: what mihomo and sing-box send by default
		"chrome",           // X25519MLKEM768 then X25519: current Chrome
	} {
		if err := realityVLESS(n, fp); err != nil {
			t.Errorf("fingerprint %s: %v", fp, err)
		}
	}
}

// realitySettings is the REALITY config buildInbound produced for xray.
func realitySettings(t *testing.T, in *core.InboundHandlerConfig) *reality.Config {
	t.Helper()
	rs, err := in.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	for _, tm := range rs.(*proxyman.ReceiverConfig).StreamSettings.SecuritySettings {
		inst, err := tm.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if rc, ok := inst.(*reality.Config); ok {
			return rc
		}
	}
	t.Fatal("no REALITY settings on the inbound")
	return nil
}

// What reaches xray for minClientVer: an empty panel value must arrive as an
// explicit 0.0.0, since xray v26 replaces an empty one with 26.3.27 and then
// refuses every sing-box and mihomo user; an operator's value is kept.
func TestRealityMinClientVerReachesXray(t *testing.T) {
	priv := make([]byte, 32)
	_, _ = rand.Read(priv)
	for in, want := range map[string]string{"": "000", "1.8.0": "180", "26.3.27": "26327"} {
		v := &panel.VAllssNode{Network: "tcp", TlsSettings: panel.TlsSettings{
			ServerName: realityTestSNI, ServerPort: "443", ShortId: "0123abcd",
			PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
		}}
		v.RealityConfig.MinClientVer = in
		v.ServerPort = 443
		info := &panel.NodeInfo{Type: "vless", Security: panel.Reality, VAllss: v, Common: &v.CommonNode}
		ib, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}, info, "t")
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		got := ""
		for _, b := range realitySettings(t, ib).MinClientVer {
			got += strconv.Itoa(int(b))
		}
		if got != want {
			t.Errorf("minClientVer %q reached xray as %v, want %s", in, realitySettings(t, ib).MinClientVer, want)
		}
	}
}

// The panel's MaxTimeDiff is a Go duration; xray's maxTimeDiff is in
// milliseconds. It was handed microseconds, so "90s" allowed a client clock
// 25 hours off - a replayed ClientHello stayed usable for a day.
func TestRealityMaxTimeDiffIsMilliseconds(t *testing.T) {
	priv := make([]byte, 32)
	_, _ = rand.Read(priv)
	for in, want := range map[string]uint64{"": 0, "90s": 90_000, "2m": 120_000, "1500ms": 1_500} {
		v := &panel.VAllssNode{Network: "tcp", TlsSettings: panel.TlsSettings{
			ServerName: realityTestSNI, ServerPort: "443", ShortId: "0123abcd",
			PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
		}}
		v.RealityConfig.MaxTimeDiff = in
		v.ServerPort = 443
		info := &panel.NodeInfo{Type: "vless", Security: panel.Reality, VAllss: v, Common: &v.CommonNode}
		ib, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}, info, "t")
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := realitySettings(t, ib).MaxTimeDiff; got != want {
			t.Errorf("MaxTimeDiff %q: xray got %d ms, want %d", in, got, want)
		}
	}
}

// Strangers relayed to the borrowed site run at full speed for the first
// 4 MiB of a connection - any page load - and are held to 64 KiB/s after, so
// the node's address cannot be used as a free bulk relay. An operator can
// change both, or turn the limit off.
func TestRealityFallbackIsLimited(t *testing.T) {
	priv := make([]byte, 32)
	_, _ = rand.Read(priv)
	build := func(xo *conf.XrayOptions) *reality.Config {
		v := &panel.VAllssNode{Network: "tcp", TlsSettings: panel.TlsSettings{
			ServerName: realityTestSNI, ServerPort: "443", ShortId: "0123abcd",
			PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
		}}
		v.ServerPort = 443
		info := &panel.NodeInfo{Type: "vless", Security: panel.Reality, VAllss: v, Common: &v.CommonNode}
		ib, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", XrayOptions: xo}, info, "t")
		if err != nil {
			t.Fatal(err)
		}
		return realitySettings(t, ib)
	}
	check := func(name string, rc *reality.Config, after, rate uint64) {
		t.Helper()
		for dir, l := range map[string]*reality.LimitFallback{"upload": rc.LimitFallbackUpload, "download": rc.LimitFallbackDownload} {
			if l.GetAfterBytes() != after || l.GetBytesPerSec() != rate {
				t.Errorf("%s %s: after %d B at %d B/s, want %d at %d", name, dir, l.GetAfterBytes(), l.GetBytesPerSec(), after, rate)
			}
			if rate > 0 && l.GetBurstBytesPerSec() < rate {
				t.Errorf("%s %s: burst %d below the rate %d", name, dir, l.GetBurstBytesPerSec(), rate)
			}
		}
	}
	check("default", build(conf.NewXrayOptions()), 4096*1024, 64*1024)
	custom := conf.NewXrayOptions()
	custom.RealityFallbackAfterKB, custom.RealityFallbackKBps = 1024, 256
	check("custom", build(custom), 1024*1024, 256*1024)
	off := conf.NewXrayOptions()
	off.RealityFallbackKBps = -1
	check("off", build(off), 0, 0)
}
