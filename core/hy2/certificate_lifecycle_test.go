package hy2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/internal/certtest"
	"github.com/apernet/quic-go"
)

func hyCertificateCore(t *testing.T) *Hysteria2 {
	t.Helper()
	c, err := New(&conf.CoreConfig{Type: "hysteria2", Hysteria2Config: conf.NewHysteria2Config()})
	if err != nil {
		t.Fatal(err)
	}
	h := c.(*Hysteria2)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// A free UDP port can already belong to an unrelated TCP service. Reserve both
// transports until immediately before AddNode, without disturbing that service.
func hyCertificatePort(t *testing.T) (int, func()) {
	t.Helper()
	for attempt := 0; attempt < 30; attempt++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err == nil {
			release := func() { _ = udp.Close(); _ = tcp.Close() }
			t.Cleanup(release)
			return port, release
		}
		_ = tcp.Close()
	}
	t.Fatal("could not reserve a matching free TCP and UDP port")
	return 0, func() {}
}

func hyCertificateNode(port int) *panel.NodeInfo {
	n := &panel.Hysteria2Node{CommonNode: panel.CommonNode{ServerPort: port}}
	return &panel.NodeInfo{Type: "hysteria2", Security: panel.Tls, Hysteria2: n, Common: &n.CommonNode}
}

func hyCertificateProbe(port int, roots *x509.CertPool, transport string) (int64, error) {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	// Each call uses a fresh connection, configuration and transport. A resumed
	// TLS session or reused HTTP/3 connection must not mask certificate rotation.
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "rotation.test", MinVersion: tls.VersionTLS12}
	if transport == "tcp" {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, tlsConfig)
		if err != nil {
			return 0, err
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), nil
	}
	tlsConfig.NextProtos = []string{"h3"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, address, tlsConfig, &quic.Config{})
	if err != nil {
		return 0, err
	}
	defer c.CloseWithError(0, "")
	return c.ConnectionState().TLS.PeerCertificates[0].SerialNumber.Int64(), nil
}

func awaitHyCertificate(t *testing.T, port int, roots *x509.CertPool, want int64) {
	t.Helper()
	for _, transport := range []string{"quic", "tcp"} {
		deadline := time.Now().Add(5 * time.Second)
		var got int64
		var err error
		for time.Now().Before(deadline) {
			got, err = hyCertificateProbe(port, roots, transport)
			if err == nil && got == want {
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		if err != nil || got != want {
			t.Fatalf("verified Hysteria2 %s serial=%d error=%v, want %d without restarting the node", transport, got, err, want)
		}
	}
}

func TestHy2_CertificateModesUseSameQUICAndTCPPaths(t *testing.T) {
	ca := certtest.NewAuthority(t)
	now := time.Now()
	leaf := ca.Issue(t, "rotation.test", 11, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for _, mode := range []string{"file", "http", "dns", "self"} {
		t.Run(mode, func(t *testing.T) {
			h := hyCertificateCore(t)
			dir := t.TempDir()
			cp, kp := filepath.Join(dir, "rotation.test.pem"), filepath.Join(dir, "rotation.test.key")
			certtest.Write(t, cp, kp, leaf)
			// Issuance is tested by the certificate manager. Every enabled mode
			// must consume its resolved on-disk paths in both serving transports.
			cfg := &conf.CertConfig{CertMode: mode, CertDomain: "rotation.test", CertFile: filepath.Join(dir, "{domain}.pem"), KeyFile: filepath.Join(dir, "{domain}.key")}
			// Direct configuration must resolve paths too, without depending on
			// the controller or AddNode to have modified its input first.
			tlsConfig, err := (&Hysteria2node{}).getTLSConfig(&conf.Options{CertConfig: cfg})
			if err != nil {
				t.Fatal(err)
			}
			cert, err := tlsConfig.GetCertificate(nil)
			if err != nil || cert.Leaf.SerialNumber.Int64() != 11 {
				t.Fatalf("direct TLS configuration certificate=%v error=%v", cert, err)
			}
			port, release := hyCertificatePort(t)
			release()
			if err := h.AddNode("cert-"+mode, hyCertificateNode(port), &conf.Options{ListenIP: "127.0.0.1", CertConfig: cfg}); err != nil {
				t.Fatal(err)
			}
			if n := h.node("cert-" + mode); n == nil || n.cover == nil {
				t.Fatal("the node's matching TCP cover listener did not start")
			}
			awaitHyCertificate(t, port, ca.Roots, 11)
			if !strings.Contains(cfg.CertFile, "{domain}") || !strings.Contains(cfg.KeyFile, "{domain}") {
				t.Fatal("core mutated caller-owned certificate paths")
			}
		})
	}
}

func TestHy2_RejectsInvalidCertificateBeforeListening(t *testing.T) {
	ca := certtest.NewAuthority(t)
	now := time.Now()
	valid := ca.Issue(t, "rotation.test", 1, now.Add(-time.Hour), now.Add(time.Hour))
	for _, problem := range []string{"nil config", "none", "empty mode", "unknown mode", "missing", "malformed", "mismatched key", "expired", "future", "wrong hostname"} {
		t.Run(problem, func(t *testing.T) {
			h := hyCertificateCore(t)
			dir := t.TempDir()
			cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			certtest.Write(t, cp, kp, valid)
			cfg := &conf.CertConfig{CertMode: "file", CertDomain: "rotation.test", CertFile: cp, KeyFile: kp}
			switch problem {
			case "nil config":
				cfg = nil
			case "none":
				cfg.CertMode = "none"
			case "empty mode":
				cfg.CertMode = ""
			case "unknown mode":
				cfg.CertMode = "fle"
			case "missing":
				cfg.CertFile += ".missing"
			case "malformed":
				if err := os.WriteFile(cp, []byte("incomplete PEM"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "mismatched key":
				other := ca.Issue(t, "rotation.test", 2, now.Add(-time.Hour), now.Add(time.Hour))
				certtest.Write(t, cp, kp, certtest.Pair{Certificate: valid.Certificate, Key: other.Key})
			case "expired":
				certtest.Write(t, cp, kp, ca.Issue(t, "rotation.test", 3, now.Add(-2*time.Hour), now.Add(-time.Hour)))
			case "future":
				certtest.Write(t, cp, kp, ca.Issue(t, "rotation.test", 4, now.Add(time.Hour), now.Add(2*time.Hour)))
			case "wrong hostname":
				certtest.Write(t, cp, kp, ca.Issue(t, "other.test", 5, now.Add(-time.Hour), now.Add(time.Hour)))
			}
			if _, err := (&Hysteria2node{}).getTLSConfig(&conf.Options{CertConfig: cfg}); err == nil {
				t.Fatal("direct TLS configuration accepted an invalid certificate")
			}
			port, release := hyCertificatePort(t)
			release()
			if err := h.AddNode("bad-"+problem, hyCertificateNode(port), &conf.Options{ListenIP: "127.0.0.1", CertConfig: cfg}); err == nil {
				t.Fatal("invalid TLS node started")
			}
			address := fmt.Sprintf("127.0.0.1:%d", port)
			tcp, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal("failed TLS node retained a TCP listener", err)
			}
			_ = tcp.Close()
			udp, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal("failed TLS node retained a UDP listener", err)
			}
			_ = udp.Close()
		})
	}
}

func TestHy2_RejectsNilCertificateOptions(t *testing.T) {
	if _, err := (&Hysteria2node{}).getTLSConfig(nil); err == nil {
		t.Fatal("direct TLS configuration accepted nil options")
	}
	h := hyCertificateCore(t)
	if err := h.AddNode("nil-options", hyCertificateNode(0), nil); err == nil {
		t.Fatal("node accepted nil options")
	}
}

func TestHy2_CertificateRotationOnLiveQUICAndTCP(t *testing.T) {
	h := hyCertificateCore(t)
	ca := certtest.NewAuthority(t)
	now := time.Now()
	first := ca.Issue(t, "rotation.test", 1, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	second := ca.Issue(t, "rotation.test", 2, now.Add(-time.Hour), now.Add(91*24*time.Hour))
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certtest.Write(t, cp, kp, first)
	port, release := hyCertificatePort(t)
	release()
	if err := h.AddNode("rotation", hyCertificateNode(port), &conf.Options{ListenIP: "127.0.0.1", CertConfig: &conf.CertConfig{CertMode: "file", CertDomain: "rotation.test", CertFile: cp, KeyFile: kp}}); err != nil {
		t.Fatal(err)
	}
	node := h.node("rotation")
	if node == nil || node.cover == nil {
		t.Fatal("the node's matching TCP cover listener did not start")
	}
	awaitHyCertificate(t, port, ca.Roots, 1)
	for _, bad := range []struct {
		name string
		pair certtest.Pair
	}{
		{"partial certificate", certtest.Pair{Certificate: []byte("partially installed certificate"), Key: first.Key}},
		{"mismatched key", certtest.Pair{Certificate: first.Certificate, Key: second.Key}},
		{"expired", ca.Issue(t, "rotation.test", 3, now.Add(-2*time.Hour), now.Add(-time.Hour))},
		{"future", ca.Issue(t, "rotation.test", 4, now.Add(time.Hour), now.Add(2*time.Hour))},
		{"wrong hostname", ca.Issue(t, "other.test", 5, now.Add(-time.Hour), now.Add(time.Hour))},
	} {
		t.Run(bad.name, func(t *testing.T) {
			certtest.Write(t, cp, kp, bad.pair)
			// Both loaders check no more than once per second. Ensure a new
			// handshake actually attempts to load this replacement.
			time.Sleep(1100 * time.Millisecond)
			awaitHyCertificate(t, port, ca.Roots, 1)
		})
	}
	certtest.Write(t, cp, kp, second)
	awaitHyCertificate(t, port, ca.Roots, 2)
	if h.node("rotation") != node {
		t.Fatal("certificate rotation replaced the running node")
	}
}

func TestHy2_ConfiguredMasqueradeCertificateRotation(t *testing.T) {
	h := hyCertificateCore(t)
	ca := certtest.NewAuthority(t)
	now := time.Now()
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "rotation.test.pem"), filepath.Join(dir, "rotation.test.key")
	certtest.Write(t, cp, kp, ca.Issue(t, "rotation.test", 1, now.Add(-time.Hour), now.Add(90*24*time.Hour)))
	port, release := hyCertificatePort(t)
	path := filepath.Join(dir, "hysteria2.yaml")
	configuration := fmt.Sprintf("masquerade:\n  type: string\n  string:\n    content: local TLS lifecycle test\n  listenHTTPS: 127.0.0.1:%d\n", port)
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	options := &conf.Options{ListenIP: "127.0.0.1", Hysteria2ConfigPath: path, CertConfig: &conf.CertConfig{
		CertMode: "file", CertDomain: "rotation.test", CertFile: filepath.Join(dir, "{domain}.pem"), KeyFile: filepath.Join(dir, "{domain}.key"),
	}}
	release()
	if err := h.AddNode("configured-masquerade", hyCertificateNode(port), options); err != nil {
		t.Fatal(err)
	}
	if n := h.node("configured-masquerade"); n == nil || n.masq == nil || n.cover != nil {
		t.Fatal("the configured HTTPS masquerade did not own the TCP listener")
	}
	awaitHyCertificate(t, port, ca.Roots, 1)
	certtest.Write(t, cp, kp, ca.Issue(t, "rotation.test", 2, now.Add(-time.Hour), now.Add(91*24*time.Hour)))
	awaitHyCertificate(t, port, ca.Roots, 2)
}
