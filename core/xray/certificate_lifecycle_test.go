package xray

import (
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
)

func certificateXrayCore(t *testing.T) *Xray {
	t.Helper()
	c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: conf.NewXrayConfig()})
	if err != nil {
		t.Fatal(err)
	}
	x := c.(*Xray)
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })
	return x
}

func certificateXrayNode(kind string, port int) *panel.NodeInfo {
	common := panel.CommonNode{ServerPort: port}
	n := &panel.NodeInfo{Type: kind, Security: panel.Tls}
	if kind == "trojan" {
		n.Trojan = &panel.TrojanNode{CommonNode: common, Network: "tcp"}
		n.Common = &n.Trojan.CommonNode
	} else {
		n.VAllss = &panel.VAllssNode{CommonNode: common, Network: "tcp"}
		n.Common = &n.VAllss.CommonNode
	}
	return n
}

func certificateXrayOptions(c *conf.CertConfig) *conf.Options {
	xo := conf.NewXrayOptions()
	xo.DecoySite = new(false)
	return &conf.Options{ListenIP: "127.0.0.1", XrayOptions: xo, CertConfig: c}
}

func certificateXrayProbe(port int, roots *x509.CertPool) (int64, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{RootCAs: roots, ServerName: "rotation.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), nil
}

func awaitXrayCertificate(t *testing.T, port int, roots *x509.CertPool, want int64) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var got int64
	var err error
	for time.Now().Before(deadline) {
		got, err = certificateXrayProbe(port, roots)
		if err == nil && got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("verified Xray TLS serial=%d error=%v, want %d without restarting the node", got, err, want)
}

func TestXray_TLSCertificateModesUseSameLivePaths(t *testing.T) {
	ca := certtest.NewAuthority(t)
	now := time.Now()
	leaf := ca.Issue(t, "rotation.test", 11, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		for _, mode := range []string{"file", "http", "dns", "self"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				x := certificateXrayCore(t)
				dir := t.TempDir()
				cp, kp := filepath.Join(dir, "rotation.test.pem"), filepath.Join(dir, "rotation.test.key")
				certtest.Write(t, cp, kp, leaf)
				// All enabled modes consume the same validated paths. Issuance
				// belongs to the certificate manager and is not performed here.
				c := &conf.CertConfig{CertMode: mode, CertDomain: "rotation.test", CertFile: filepath.Join(dir, "{domain}.pem"), KeyFile: filepath.Join(dir, "{domain}.key")}
				port := freePort(t)
				if err := x.AddNode("cert-"+kind+"-"+mode, certificateXrayNode(kind, port), certificateXrayOptions(c)); err != nil {
					t.Fatal(err)
				}
				awaitXrayCertificate(t, port, ca.Roots, 11)
				if !strings.Contains(c.CertFile, "{domain}") {
					t.Fatal("core mutated caller-owned certificate options")
				}
			})
		}
	}
}

func TestXray_RejectsInvalidTLSBeforeNodeStart(t *testing.T) {
	x := certificateXrayCore(t)
	ca := certtest.NewAuthority(t)
	now := time.Now()
	valid := ca.Issue(t, "rotation.test", 1, now.Add(-time.Hour), now.Add(time.Hour))
	for _, problem := range []string{"unknown mode", "missing", "malformed", "mismatched key", "expired", "future", "wrong hostname"} {
		t.Run(problem, func(t *testing.T) {
			dir := t.TempDir()
			cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			certtest.Write(t, cp, kp, valid)
			c := &conf.CertConfig{CertMode: "file", CertDomain: "rotation.test", CertFile: cp, KeyFile: kp}
			switch problem {
			case "unknown mode":
				c.CertMode = "fle"
			case "missing":
				c.CertFile += ".missing"
			case "malformed":
				if err := os.WriteFile(cp, []byte("incomplete PEM"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "mismatched key":
				other := ca.Issue(t, "rotation.test", 2, now.Add(-time.Hour), now.Add(time.Hour))
				if err := os.WriteFile(kp, other.Key, 0o600); err != nil {
					t.Fatal(err)
				}
			case "expired":
				certtest.Write(t, cp, kp, ca.Issue(t, "rotation.test", 3, now.Add(-2*time.Hour), now.Add(-time.Hour)))
			case "future":
				certtest.Write(t, cp, kp, ca.Issue(t, "rotation.test", 4, now.Add(time.Hour), now.Add(2*time.Hour)))
			case "wrong hostname":
				certtest.Write(t, cp, kp, ca.Issue(t, "other.test", 5, now.Add(-time.Hour), now.Add(time.Hour)))
			}
			port := freePort(t)
			if err := x.AddNode("bad-"+problem, certificateXrayNode("vless", port), certificateXrayOptions(c)); err == nil {
				t.Fatal("invalid TLS node started")
			}
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				t.Fatal("failed TLS node retained its listener", err)
			}
			_ = ln.Close()
		})
	}
}

func TestXray_TLSLiveCertificateRotationWithoutRestart(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			x := certificateXrayCore(t)
			ca := certtest.NewAuthority(t)
			now := time.Now()
			first := ca.Issue(t, "rotation.test", 1, now.Add(-time.Hour), now.Add(time.Hour))
			second := ca.Issue(t, "rotation.test", 2, now.Add(-time.Hour), now.Add(2*time.Hour))
			dir := t.TempDir()
			cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			certtest.Write(t, cp, kp, first)
			port := freePort(t)
			if err := x.AddNode("rotate-"+kind, certificateXrayNode(kind, port), certificateXrayOptions(&conf.CertConfig{CertMode: "file", CertDomain: "rotation.test", CertFile: cp, KeyFile: kp})); err != nil {
				t.Fatal(err)
			}
			awaitXrayCertificate(t, port, ca.Roots, 1)
			if kind == "vless" {
				for _, bad := range []certtest.Pair{
					{Certificate: []byte("partially installed certificate"), Key: first.Key},
					ca.Issue(t, "rotation.test", 3, now.Add(-2*time.Hour), now.Add(-time.Hour)),
					ca.Issue(t, "other.test", 4, now.Add(-time.Hour), now.Add(time.Hour)),
					ca.IssueWithUnknownUsage(t, []string{"rotation.test"}, 5, now.Add(-time.Hour), now.Add(time.Hour)),
				} {
					certtest.Write(t, cp, kp, bad)
					time.Sleep(5100 * time.Millisecond)
					awaitXrayCertificate(t, port, ca.Roots, 1)
				}
			}
			certtest.Write(t, cp, kp, second)
			awaitXrayCertificate(t, port, ca.Roots, 2)
		})
	}
}

func TestXray_ConfiguredDomainRenewalDropsObsoleteSAN(t *testing.T) {
	x := certificateXrayCore(t)
	ca := certtest.NewAuthority(t)
	now := time.Now()
	first := ca.IssueNames(t, []string{"rotation.test", "obsolete.test"}, 1, now.Add(-time.Hour), now.Add(time.Hour))
	second := ca.Issue(t, "rotation.test", 2, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	certtest.Write(t, cp, kp, first)
	port := freePort(t)
	if err := x.AddNode("scoped-renewal", certificateXrayNode("vless", port), certificateXrayOptions(&conf.CertConfig{CertMode: "http", CertDomain: "rotation.test", CertFile: cp, KeyFile: kp})); err != nil {
		t.Fatal(err)
	}
	awaitXrayCertificate(t, port, ca.Roots, 1)
	certtest.Write(t, cp, kp, second)
	awaitXrayCertificate(t, port, ca.Roots, 2)
}
