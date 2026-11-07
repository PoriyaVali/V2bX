package cmd

// Every node Irboard's admin forms make, as Irboard serves it, on every V2bX
// core that can serve it, reached the way Irboard's subscribers reach it.
//
// api/panel/testdata/irboard/served.json is exported by Irboard's
// tests/Feature/ServedNodeContractTest.php. For each node it holds the config
// and user list UniProxy gives V2bX, and the Clash Meta proxy, sing-box
// outbound and share link a subscriber gets. Each node is started through
// V2bX's own node controller, from that config and user list, on each core
// validateSetupCore accepts for it. Then each client connects through it:
//
//   - mihomo, from the Clash Meta proxy (core/xray/testdata/mihomoclient);
//   - sing-box, from the outbound;
//   - Xray, from the share link, read the way v2rayN and v2rayNG read one.
//
// The test changes only what a test cannot have. The node listens on a free
// local port, and every client is pointed at it. A REALITY node borrows a
// local TLS 1.3 site instead of the real one. A TLS client trusts the node's
// self-signed certificate.
//
// Built without the release tags, sing-box lacks QUIC (Hysteria, TUIC) and
// uTLS (REALITY, fingerprints). What needs them is skipped; CI runs the
// test again with the release tags.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	_ "github.com/PoriyaVali/V2bX/core/hy2"
	_ "github.com/PoriyaVali/V2bX/core/mihomo"
	_ "github.com/PoriyaVali/V2bX/core/sing"
	_ "github.com/PoriyaVali/V2bX/core/xray"
	"github.com/PoriyaVali/V2bX/node"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const servedHost = "node.example.test"

// servedCores are the cores a VLESS, VMess, Trojan, Shadowsocks, Hysteria,
// TUIC or AnyTLS node can be placed on.
var servedCores = []string{"xray", "sing", "mihomo", "hysteria2"}

// Profiles Irboard leaves out on purpose, because the client cannot reach
// the node: mihomo and sing-box have no mKCP, sing-box no XHTTP and no VLESS
// encryption, and mihomo no VMess over XHTTP.
var servedWithout = map[string][]string{
	"clash":   {"vless/kcp", "vmess/kcp", "vmess/xhttp"},
	"singbox": {"vless/kcp", "vless/xhttp-reality", "vless/xhttp-tls-padding", "vless/tcp-reality-encryption", "vmess/kcp", "vmess/xhttp"},
}

type servedResponse struct {
	Body        []byte `json:"body"`
	ContentType string `json:"content_type"`
	ETag        string `json:"etag"`
}

type servedNode struct {
	NodeType string         `json:"node_type"`
	NodeID   int            `json:"node_id"`
	Config   servedResponse `json:"config"`
	Users    servedResponse `json:"users"`
	Clash    map[string]any `json:"clash"`
	Singbox  map[string]any `json:"singbox"`
	Link     string         `json:"link"`
}

// notInThisBuild is how sing-box refuses what needs a build tag.
func notInThisBuild(err error) bool {
	return err != nil && strings.Contains(err.Error(), "is not included in this build")
}

func TestIrboardServedNodesOnEveryCore(t *testing.T) {
	raw, err := os.ReadFile("../api/panel/testdata/irboard/served.json")
	if err != nil {
		t.Fatal(err)
	}
	var served struct {
		UUID  string                `json:"uuid"`
		Nodes map[string]servedNode `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &served); err != nil {
		t.Fatal(err)
	}
	if len(served.Nodes) == 0 {
		t.Fatal("served.json has no nodes")
	}
	names := make([]string, 0, len(served.Nodes))
	for name := range served.Nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	cert := servedCertificate(t)
	echo := servedEcho(t)
	mihomo := buildMihomoClient(t)
	for _, name := range names {
		n := served.Nodes[name]
		t.Run(name, func(t *testing.T) {
			for client, without := range servedWithout {
				left := false
				for _, w := range without {
					left = left || w == name
				}
				has := map[string]bool{"clash": n.Clash != nil, "singbox": n.Singbox != nil}[client]
				if !left && !has {
					t.Errorf("Irboard gives %s clients nothing for this node", client)
				}
			}
			info := servedNodeInfo(t, n)
			auto := resolveSetupCore("auto", info)
			if err := validateSetupCore(auto, info); err != nil {
				t.Errorf("the wizard's automatic choice, %s, cannot serve the node: %v", auto, err)
			}
			for _, core := range servedCores {
				if validateSetupCore(core, info) != nil {
					continue
				}
				t.Run(core, func(t *testing.T) {
					port, err := startServedNode(t, n, core, cert)
					if notInThisBuild(err) {
						t.Skip(err)
					}
					if err != nil {
						t.Fatalf("the node did not start: %v", err)
					}
					if n.Clash != nil {
						if err := dialClash(t, mihomo, n.Clash, port, echo); err != nil {
							t.Errorf("mihomo, with the Clash Meta proxy: %v", err)
						}
					}
					if n.Singbox != nil {
						err := dialSingbox(t, n.Singbox, port, echo)
						if notInThisBuild(err) {
							t.Logf("sing-box client skipped: %v", err)
						} else if err != nil {
							t.Errorf("sing-box, with the outbound: %v", err)
						}
					}
					err = dialLink(n.Link, port, echo, cert.sha256)
					if errors.Is(err, errNotAnXrayLink) {
						return
					}
					if err != nil {
						t.Errorf("Xray, with the share link: %v", err)
					}
				})
			}
		})
	}
}

// servedNodeInfo is the node as V2bX's panel client reads Irboard's config.
func servedNodeInfo(t *testing.T, n servedNode) *panel.NodeInfo {
	t.Helper()
	srv := servedPanel(n, n.Config.Body)
	defer srv.Close()
	api, err := panel.New(&conf.ApiConfig{APIHost: srv.URL, NodeID: n.NodeID, NodeType: n.NodeType, Key: "contract-token", Timeout: 10})
	if err != nil {
		t.Fatal(err)
	}
	info, err := api.GetNodeInfo()
	if err != nil {
		t.Fatalf("V2bX cannot read the node's config: %v", err)
	}
	return info
}

// servedPanel answers V2bX as Irboard did, with config as the node's config.
func servedPanel(n servedNode, config []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "contract-token" {
			http.Error(w, "token", http.StatusForbidden)
			return
		}
		respond := func(res servedResponse, body []byte) {
			if res.ETag != "" && r.Header.Get("If-None-Match") == res.ETag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", res.ContentType)
			if res.ETag != "" {
				w.Header().Set("ETag", res.ETag)
			}
			_, _ = w.Write(body)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			respond(n.Config, config)
		case "/api/v1/server/UniProxy/user":
			respond(n.Users, n.Users.Body)
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			_, _ = w.Write([]byte(`{"data":true}`))
		}
	}))
}

// servedConfig is the node's config listening on port, and for a REALITY
// node borrowing site.
func servedConfig(body []byte, port int, site string) ([]byte, error) {
	var config map[string]any
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	config["server_port"] = port
	if site != "" {
		settings, ok := config["tls_settings"].(map[string]any)
		if !ok {
			return nil, errors.New("a REALITY node without tls_settings")
		}
		host, sitePort, _ := net.SplitHostPort(site)
		settings["dest"], settings["server_port"] = host, sitePort
	}
	return json.Marshal(config)
}

// startServedNode runs the node on core through V2bX's node controller and
// returns its port.
func startServedNode(t *testing.T, n servedNode, core string, cert servedCert) (int, error) {
	t.Helper()
	var head struct {
		TLS int `json:"tls"`
	}
	_ = json.Unmarshal(n.Config.Body, &head)
	site := ""
	if head.TLS == panel.Reality {
		site = servedSite(t)
	}
	port := servedPort(t)
	config, err := servedConfig(n.Config.Body, port, site)
	if err != nil {
		t.Fatal(err)
	}
	srv := servedPanel(n, config)
	t.Cleanup(srv.Close)

	cc := conf.CoreConfig{Type: core}
	switch core {
	case "xray":
		cc.XrayConfig = conf.NewXrayConfig()
		cc.XrayConfig.LogConfig.Level = "none"
		cc.XrayConfig.AllowPrivateDestinations = true
	case "sing":
		cc.SingConfig = conf.NewSingConfig()
		cc.SingConfig.LogConfig.Disabled = true
		cc.SingConfig.AllowPrivateDestinations = true
	case "mihomo":
		cc.MihomoConfig = conf.NewMihomoConfig()
		cc.MihomoConfig.LogConfig.Level = "error"
		cc.MihomoConfig.AllowPrivateDestinations = true
	case "hysteria2":
		cc.Hysteria2Config = conf.NewHysteria2Config()
		cc.Hysteria2Config.AllowPrivateDestinations = true
	}
	server, err := vCore.NewCore([]conf.CoreConfig{cc})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	api, err := panel.New(&conf.ApiConfig{APIHost: srv.URL, NodeID: n.NodeID, NodeType: n.NodeType, Key: "contract-token", Timeout: 10})
	if err != nil {
		t.Fatal(err)
	}
	options := &conf.Options{}
	raw := fmt.Sprintf(`{"Core":%q,"ListenIP":"127.0.0.1","CertConfig":{"CertMode":"file","CertDomain":%q,"CertFile":%q,"KeyFile":%q}}`,
		core, servedHost, cert.file, cert.key)
	if err := options.UnmarshalJSON([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	controller := node.NewController(server, api, options)
	if err := controller.Start(); err != nil {
		return 0, err
	}
	t.Cleanup(func() { _ = controller.Close() })
	return port, nil
}

// servedPort is free for both TCP and UDP: QUIC nodes take the UDP port and
// their cover site the TCP one.
func servedPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = ln.Close()
		if err == nil {
			_ = pc.Close()
			return port
		}
	}
	t.Fatal("no port free for both TCP and UDP")
	return 0
}

type servedCert struct{ file, key, sha256 string }

// servedCertificate is a self-signed certificate for the node's host.
func servedCertificate(t *testing.T) servedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: servedHost}, DNSNames: []string{servedHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
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
	c := servedCert{file: filepath.Join(dir, "cert.pem"), key: filepath.Join(dir, "key.pem")}
	if err := os.WriteFile(c.file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	c.sha256 = hex.EncodeToString(sum[:])
	return c
}

// servedSite stands in for the site a REALITY node borrows: an ordinary TLS
// 1.3 server, which the node relays unauthenticated handshakes to.
func servedSite(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "cover.example.test"},
		DNSNames: []string{"cover.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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

// servedEcho answers every connection with whatever it is sent.
func servedEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// echoes writes through conn and wants it back. A connection the node keeps
// open but silent is closed after 15 seconds: an Xray client's connection
// does not honour deadlines.
func echoes(conn net.Conn) error {
	done := make(chan error, 1)
	go func() {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != "ping" {
			done <- fmt.Errorf("echoed %q", buf)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		_ = conn.Close()
		<-done
		return errors.New("nothing came back in 15 seconds")
	}
}

// clone copies a profile entry, so that pointing it at the test node leaves
// the fixture as Irboard made it.
func clone(v map[string]any) map[string]any {
	raw, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// buildMihomoClient builds core/xray/testdata/mihomoclient into the test's
// own temporary directory, removed with it.
func buildMihomoClient(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mihomoclient")
	if out, err := exec.Command("go", "build", "-o", path, "../core/xray/testdata/mihomoclient").CombinedOutput(); err != nil {
		t.Fatalf("build the mihomo client: %v\n%s", err, out)
	}
	return path
}

// dialClash connects through the node with the mihomo client, from the
// Clash Meta proxy, pointed at the test node and trusting its certificate.
func dialClash(t *testing.T, client string, proxy map[string]any, port int, echo string) error {
	t.Helper()
	p := clone(proxy)
	p["server"], p["port"] = "127.0.0.1", port
	if _, ok := p["skip-cert-verify"]; ok || p["tls"] == true {
		p["skip-cert-verify"] = true
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	profile := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(profile, raw, 0o600); err != nil {
		return err
	}
	out, err := exec.Command(client, profile, echo).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// dialSingbox connects through the node with sing-box, from the outbound,
// pointed at the test node and trusting its certificate.
func dialSingbox(t *testing.T, outbound map[string]any, port int, echo string) error {
	t.Helper()
	o := clone(outbound)
	o["tag"], o["server"], o["server_port"] = "proxy", "127.0.0.1", port
	if settings, ok := o["tls"].(map[string]any); ok && settings["enabled"] == true {
		if reality, ok := settings["reality"].(map[string]any); !ok || reality["enabled"] != true {
			settings["insecure"] = true
		}
	}
	socks := servedPort(t)
	config, err := json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": socks}},
		"outbounds": []any{o},
		"route":     map[string]any{"final": "proxy"},
	})
	if err != nil {
		return err
	}
	ctx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(),
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	client, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return err
	}
	if err := client.Start(); err != nil {
		_ = client.Close()
		return err
	}
	defer client.Close()
	conn, err := socksConnect(socks, echo)
	if err != nil {
		return err
	}
	defer conn.Close()
	return echoes(conn)
}

// socksConnect opens a CONNECT to target through a SOCKS5 inbound.
func socksConnect(port int, target string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(ps)
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("target %s is not IPv4", target)
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		c.Close()
		return nil, err
	}
	req := append([]byte{5, 1, 0, 1}, ip...)
	req = binary.BigEndian.AppendUint16(req, uint16(p))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	head := make([]byte, 10)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, fmt.Errorf("connect: %w", err)
	}
	if head[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("connect refused (SOCKS reply %d)", head[1])
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

var errNotAnXrayLink = errors.New("not a protocol Xray clients import")

// dialLink connects through the node with Xray, from the share link, pointed
// at the test node and pinning its certificate: Xray 26 clients cannot skip
// verification.
func dialLink(link string, port int, echo, pin string) error {
	outbound, err := linkOutbound(link, port, pin)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{outbound}})
	if err != nil {
		return err
	}
	var cfg coreConf.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("client config: %w", err)
	}
	pb, err := cfg.Build()
	if err != nil {
		return fmt.Errorf("client config: %w", err)
	}
	inst, err := xcore.New(pb)
	if err != nil {
		return err
	}
	if err := inst.Start(); err != nil {
		return err
	}
	defer inst.Close()
	host, ps, _ := net.SplitHostPort(echo)
	p, _ := strconv.Atoi(ps)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := xcore.Dial(ctx, inst, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(p)))
	if err != nil {
		return err
	}
	defer conn.Close()
	return echoes(conn)
}

// linkParams are a share link's transport and security parameters.
type linkParams struct {
	network, security                              string
	host, path, headerType, serviceName, authority string
	mode, extra, seed                              string
	sni, fingerprint, alpn, publicKey, shortID     string
	spiderX                                        string
}

// linkOutbound is the Xray outbound a v2rayN-style client imports from link,
// pointed at port.
func linkOutbound(link string, port int, pin string) (map[string]any, error) {
	scheme, _, _ := strings.Cut(link, "://")
	switch scheme {
	case "vmess":
		return vmessLink(link, port, pin)
	case "vless", "trojan", "ss":
	default:
		return nil, errNotAnXrayLink
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	p := linkParams{
		network: q.Get("type"), security: q.Get("security"),
		host: q.Get("host"), path: q.Get("path"), headerType: q.Get("headerType"), serviceName: q.Get("serviceName"),
		authority: q.Get("authority"), mode: q.Get("mode"), extra: q.Get("extra"), seed: q.Get("seed"),
		sni: q.Get("sni"), fingerprint: q.Get("fp"), alpn: q.Get("alpn"), publicKey: q.Get("pbk"), shortID: q.Get("sid"),
		spiderX: q.Get("spx"),
	}
	switch scheme {
	case "vless":
		stream, err := linkStream(p, pin)
		if err != nil {
			return nil, err
		}
		encryption := q.Get("encryption")
		if encryption == "" {
			encryption = "none"
		}
		user := map[string]any{"id": u.User.Username(), "encryption": encryption}
		if flow := q.Get("flow"); flow != "" {
			user["flow"] = flow
		}
		return map[string]any{"protocol": "vless", "streamSettings": stream,
			"settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{user}}}}}, nil
	case "trojan":
		if p.security == "" {
			p.security = "tls"
		}
		if p.sni == "" {
			p.sni = q.Get("peer")
		}
		stream, err := linkStream(p, pin)
		if err != nil {
			return nil, err
		}
		return map[string]any{"protocol": "trojan", "streamSettings": stream,
			"settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": port, "password": u.User.Username()}}}}, nil
	default: // ss, SIP002: the user info is "method:password", in base64 or not.
		method, password, ok := u.User.Username(), "", false
		if password, ok = u.User.Password(); !ok {
			decoded, err := decodeBase64(method)
			if err != nil {
				return nil, fmt.Errorf("ss user info: %w", err)
			}
			if method, password, ok = strings.Cut(string(decoded), ":"); !ok {
				return nil, errors.New("ss user info has no method")
			}
		}
		return map[string]any{"protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": port, "method": method, "password": password}}}}, nil
	}
}

// vmessLink reads v2rayN's VMess link: base64 JSON.
func vmessLink(link string, port int, pin string) (map[string]any, error) {
	raw, err := decodeBase64(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	s := func(key string) string {
		switch x := v[key].(type) {
		case string:
			return x
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return ""
	}
	p := linkParams{network: s("net"), host: s("host"), path: s("path"), headerType: s("type"),
		sni: s("sni"), fingerprint: s("fp"), alpn: s("alpn"), mode: s("mode")}
	if s("tls") == "tls" {
		p.security = "tls"
	}
	switch p.network {
	case "grpc":
		p.serviceName, p.authority = p.path, p.host
		if p.headerType == "multi" {
			p.mode = "multi"
		}
	case "kcp":
		p.seed = p.path
	}
	stream, err := linkStream(p, pin)
	if err != nil {
		return nil, err
	}
	aid, _ := strconv.Atoi(s("aid"))
	security := s("scy")
	if security == "" {
		security = "auto"
	}
	user := map[string]any{"id": s("id"), "alterId": aid, "security": security}
	return map[string]any{"protocol": "vmess", "streamSettings": stream,
		"settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{user}}}}}, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// linkStream is the streamSettings a share link's parameters give, as the
// share link standard (XTLS/Xray-core discussion 716) defines them.
func linkStream(p linkParams, pin string) (map[string]any, error) {
	network := p.network
	if network == "" {
		network = "tcp"
	}
	s := map[string]any{"network": network}
	split := func(v string) []string {
		if v == "" {
			return nil
		}
		return strings.Split(v, ",")
	}
	switch network {
	case "tcp", "raw":
		if p.headerType == "http" {
			request := map[string]any{}
			if path := split(p.path); path != nil {
				request["path"] = path
			}
			if host := split(p.host); host != nil {
				request["headers"] = map[string]any{"Host": host}
			}
			s["tcpSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": request}}
		}
	case "ws":
		s["wsSettings"] = map[string]any{"path": p.path, "host": p.host}
	case "httpupgrade":
		s["httpupgradeSettings"] = map[string]any{"path": p.path, "host": p.host}
	case "grpc":
		s["grpcSettings"] = map[string]any{"serviceName": p.serviceName, "authority": p.authority, "multiMode": p.mode == "multi"}
	case "xhttp", "splithttp":
		x := map[string]any{"path": p.path, "host": p.host, "mode": p.mode}
		if p.extra != "" {
			var extra any
			if err := json.Unmarshal([]byte(p.extra), &extra); err != nil {
				return nil, fmt.Errorf("extra: %w", err)
			}
			x["extra"] = extra
		}
		s["xhttpSettings"] = x
	case "kcp", "mkcp":
		headerType := p.headerType
		if headerType == "" {
			headerType = "none"
		}
		s["kcpSettings"] = map[string]any{"header": map[string]any{"type": headerType}, "seed": p.seed}
	default:
		return nil, fmt.Errorf("the link's transport %q", network)
	}
	switch p.security {
	case "", "none":
	case "tls":
		settings := map[string]any{"serverName": p.sni, "fingerprint": p.fingerprint, "pinnedPeerCertSha256": pin}
		if alpn := split(p.alpn); alpn != nil {
			settings["alpn"] = alpn
		}
		s["security"], s["tlsSettings"] = "tls", settings
	case "reality":
		fingerprint := p.fingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		s["security"], s["realitySettings"] = "reality", map[string]any{"serverName": p.sni, "fingerprint": fingerprint,
			"password": p.publicKey, "shortId": p.shortID, "spiderX": p.spiderX}
	default:
		return nil, fmt.Errorf("the link's security %q", p.security)
	}
	return s, nil
}
