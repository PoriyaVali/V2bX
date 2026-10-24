//go:build with_quic

package sing

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/internal/certtest"
	"github.com/sagernet/quic-go"
)

func TestSing_QUICCertificateRotation(t *testing.T) {
	for _, kind := range []string{"hysteria", "hysteria2", "tuic"} {
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
			port := freeUDPPort(t)
			if err := b.AddNode("cert-"+kind, certificateNode(kind, port), opts); err != nil {
				t.Fatal(err)
			}
			alpn := "h3"
			if kind == "hysteria" {
				alpn = "hysteria"
			}
			probe := func() (int64, error) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				c, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{RootCAs: ca.Roots, ServerName: "rotation.test", NextProtos: []string{alpn}}, &quic.Config{})
				if err != nil {
					return 0, err
				}
				defer c.CloseWithError(0, "")
				return c.ConnectionState().TLS.PeerCertificates[0].SerialNumber.Int64(), nil
			}
			awaitCertificate(t, 1, probe)
			certtest.Write(t, certPath, keyPath, second)
			awaitCertificate(t, 2, probe)
		})
	}
}
