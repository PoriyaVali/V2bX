package sing

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/internal/certtest"
)

func certificateNode(kind string, port int) *panel.NodeInfo {
	common := panel.CommonNode{ServerPort: port}
	n := &panel.NodeInfo{Type: kind, Security: panel.Tls}
	switch kind {
	case "vmess", "vless":
		n.VAllss = &panel.VAllssNode{CommonNode: common, Network: "tcp"}
		n.Common = &n.VAllss.CommonNode
	case "trojan":
		n.Trojan = &panel.TrojanNode{CommonNode: common, Network: "tcp"}
		n.Common = &n.Trojan.CommonNode
	case "anytls":
		n.AnyTls = &panel.AnyTlsNode{CommonNode: common}
		n.Common = &n.AnyTls.CommonNode
	case "hysteria":
		n.Hysteria = &panel.HysteriaNode{CommonNode: common, UpMbps: 100, DownMbps: 100}
		n.Common = &n.Hysteria.CommonNode
	case "hysteria2":
		n.Hysteria2 = &panel.Hysteria2Node{CommonNode: common}
		n.Common = &n.Hysteria2.CommonNode
	case "tuic":
		n.Tuic = &panel.TuicNode{CommonNode: common}
		n.Common = &n.Tuic.CommonNode
	}
	return n
}

func TestSing_TCPCertificateRotation(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan", "anytls"} {
		t.Run(kind, func(t *testing.T) {
			b, _ := startSing(t)
			ca := certtest.NewAuthority(t)
			now := time.Now()
			first := ca.Issue(t, "rotation.test", 1, now.Add(-time.Hour), now.Add(90*24*time.Hour))
			second := ca.Issue(t, "rotation.test", 2, now.Add(-time.Hour), now.Add(91*24*time.Hour))
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
			certtest.Write(t, certPath, keyPath, first)
			opts := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions(), CertConfig: &conf.CertConfig{CertMode: "file", CertDomain: "rotation.test", CertFile: certPath, KeyFile: keyPath}}
			opts.SingOptions.DecoySite = new(false)
			port := freeTCPPort(t)
			if err := b.AddNode("cert-"+kind, certificateNode(kind, port), opts); err != nil {
				t.Fatal(err)
			}
			probe := func() (int64, error) {
				c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{RootCAs: ca.Roots, ServerName: "rotation.test", MinVersion: tls.VersionTLS12})
				if err != nil {
					return 0, err
				}
				defer c.Close()
				return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), nil
			}
			awaitCertificate(t, 1, probe)
			if kind == "vless" {
				for _, bad := range []certtest.Pair{
					{Certificate: []byte("partial PEM"), Key: first.Key},
					ca.Issue(t, "other.test", 3, now.Add(-time.Hour), now.Add(90*24*time.Hour)),
					ca.Issue(t, "rotation.test", 4, now.Add(-2*time.Hour), now.Add(-time.Hour)),
					ca.Issue(t, "rotation.test", 5, now.Add(time.Hour), now.Add(90*24*time.Hour)),
					ca.IssueWithUsage(t, []string{"rotation.test"}, 6, now.Add(-time.Hour), now.Add(90*24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}),
					ca.IssueWithUnknownUsage(t, []string{"rotation.test"}, 7, now.Add(-time.Hour), now.Add(90*24*time.Hour)),
				} {
					certtest.Write(t, certPath, keyPath, bad)
					time.Sleep(1100 * time.Millisecond)
					awaitCertificate(t, 1, probe)
				}
			}
			certtest.Write(t, certPath, keyPath, second)
			awaitCertificate(t, 2, probe)
		})
	}
}

func TestSing_CertificateModesAndRelativePaths(t *testing.T) {
	ca := certtest.NewAuthority(t)
	now := time.Now()
	leaf := ca.Issue(t, "rotation.test", 11, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for _, mode := range []string{"file", "http", "dns", "self"} {
		t.Run(mode, func(t *testing.T) {
			b, _ := startSing(t)
			dir := t.TempDir()
			cp, kp := filepath.Join(dir, "rotation.test.pem"), filepath.Join(dir, "rotation.test.key")
			certtest.Write(t, cp, kp, leaf)
			c := &conf.CertConfig{CertMode: mode, CertDomain: "rotation.test", CertFile: filepath.Join(dir, "{domain}.pem"), KeyFile: filepath.Join(dir, "{domain}.key")}
			opts := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions(), CertConfig: c}
			opts.SingOptions.DecoySite = new(false)
			port := freeTCPPort(t)
			if err := b.AddNode("modes-"+mode, certificateNode("vless", port), opts); err != nil {
				t.Fatal(err)
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{RootCAs: ca.Roots, ServerName: "rotation.test"})
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if c.CertFile != filepath.Join(dir, "{domain}.pem") {
				t.Fatal("caller options mutated")
			}
		})
	}
	t.Run("relative rotation", func(t *testing.T) {
		t.Chdir(t.TempDir())
		b, _ := startSing(t)
		certtest.Write(t, "c.pem", "k.pem", leaf)
		opts := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions(), CertConfig: &conf.CertConfig{CertMode: "file", CertDomain: "rotation.test", CertFile: "c.pem", KeyFile: "k.pem"}}
		opts.SingOptions.DecoySite = new(false)
		port := freeTCPPort(t)
		if err := b.AddNode("relative", certificateNode("vless", port), opts); err != nil {
			t.Fatal(err)
		}
		probe := func() (int64, error) {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{RootCAs: ca.Roots, ServerName: "rotation.test"})
			if err != nil {
				return 0, err
			}
			defer c.Close()
			return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), nil
		}
		awaitCertificate(t, 11, probe)
		certtest.Write(t, "c.pem", "k.pem", ca.Issue(t, "rotation.test", 12, now.Add(-time.Hour), now.Add(91*24*time.Hour)))
		awaitCertificate(t, 12, probe)
		if _, err := os.Stat("c.pem"); err != nil {
			t.Fatal(err)
		}
	})
}

func awaitCertificate(t *testing.T, want int64, probe func() (int64, error)) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	var got int64
	var err error
	for time.Now().Before(deadline) {
		got, err = probe()
		if err == nil && got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("TLS serial=%d error=%v; want %d without restarting the listener", got, err, want)
}
