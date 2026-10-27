package mihomo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/internal/certtest"
	"github.com/metacubex/quic-go"
	MTLS "github.com/metacubex/tls"
)

func verifiedCertificate(port int, roots *x509.CertPool, domain, transport string) (int64, error) {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	if transport == "tcp" {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{RootCAs: roots, ServerName: domain})
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, &MTLS.Config{RootCAs: roots, ServerName: domain, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		return 0, err
	}
	defer conn.CloseWithError(0, "")
	return conn.ConnectionState().TLS.PeerCertificates[0].SerialNumber.Int64(), nil
}

// Verify the certificates actually served by every certificate-based managed
// listener. Public ACME challenges are deliberately outside this local test.
func TestMihomoVerifiedCertificateRotation(t *testing.T) {
	for _, protocol := range []string{"http", "socks5", "vmess", "vless", "trojan", "anytls", "tuic", "hysteria2", "trusttunnel"} {
		t.Run(protocol, func(t *testing.T) {
			c, info, options := fixture(t, protocol, nil)
			info.Security = panel.Tls
			ca, now := certtest.NewAuthority(t), time.Now()
			cfg := options.CertConfig
			cfg.CertDomain = "node.example.test"
			write := func(name string, serial int64) {
				certtest.Write(t, cfg.CertFile, cfg.KeyFile, ca.Issue(t, name, serial, now.Add(-time.Hour), now.Add(90*24*time.Hour)))
			}
			write(cfg.CertDomain, 101)
			if _, err := c.AddUsers(&vCore.AddUsersParams{Tag: t.Name(), Users: []panel.UserInfo{subscriber}}); err != nil {
				t.Fatal(err)
			}
			transports := []string{"tcp"}
			if protocol == "tuic" || protocol == "hysteria2" {
				transports = []string{"quic"}
			} else if protocol == "trusttunnel" {
				transports = []string{"tcp", "quic"}
			}
			check := func(want int64) {
				t.Helper()
				for _, transport := range transports {
					got, err := verifiedCertificate(info.Common.ServerPort, ca.Roots, cfg.CertDomain, transport)
					if err != nil || got != want {
						t.Fatalf("%s verified certificate: serial=%d, error=%v, want %d", transport, got, err, want)
					}
				}
			}
			check(101)
			for _, transport := range transports {
				if _, err := verifiedCertificate(info.Common.ServerPort, ca.Roots, "wrong.example.test", transport); err == nil {
					t.Fatal("client accepted certificate for the wrong hostname")
				}
			}
			write(cfg.CertDomain, 102)
			time.Sleep(1100 * time.Millisecond) // cross the bounded file-refresh interval
			check(102)
			// An unrelated but otherwise valid certificate must not take over the
			// node. Retain the latest valid replacement, rather than the first pair.
			write("unrelated.example.test", 103)
			time.Sleep(1100 * time.Millisecond)
			check(102)
			write(cfg.CertDomain, 104)
			time.Sleep(1100 * time.Millisecond)
			check(104)
		})
	}
}
