package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
)

// targetSite serves TLS for name with a certificate that roots trusts.
func targetSite(t *testing.T, name string, maxVersion uint16) (addr string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MaxVersion:   maxVersion,
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
				_ = c.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String(), roots
}

func probe(t *testing.T, addr, serverName string, roots *x509.CertPool) realityProbe {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return probeRealityTarget(ctx, host, port, serverName, roots)
}

func TestProbeRealityTarget(t *testing.T) {
	good, roots := targetSite(t, "target.test", tls.VersionTLS13)
	if p := probe(t, good, "target.test", roots); p.err != nil || p.certErr != nil || p.elapsed <= 0 {
		t.Fatalf("a usable target: %+v", p)
	}
	// A certificate for another name is usable but tells a prober it was borrowed.
	if p := probe(t, good, "other.test", roots); p.err != nil || p.certErr == nil {
		t.Fatalf("a target whose certificate does not cover the name: %+v", p)
	}
	// REALITY needs TLS 1.3 from the target.
	old, roots12 := targetSite(t, "old.test", tls.VersionTLS12)
	if p := probe(t, old, "old.test", roots12); p.err == nil {
		t.Fatal("a TLS 1.2-only target was accepted")
	}
	closed := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return ln.Addr().String()
	}()
	if p := probe(t, closed, "target.test", roots); p.err == nil {
		t.Fatal("an unreachable target was accepted")
	}
}

func TestRealityTargetFromPanel(t *testing.T) {
	v := &panel.VAllssNode{TlsSettings: panel.TlsSettings{ServerName: "www.example.com", ServerPort: "8443"}}
	host, port, sni, ok := realityTarget(&panel.NodeInfo{Security: panel.Reality, VAllss: v, Common: &v.CommonNode})
	if !ok || host != "www.example.com" || port != "8443" || sni != "www.example.com" {
		t.Fatalf("dest defaults to the server name: %s %s %s %v", host, port, sni, ok)
	}
	a := &panel.AnyTlsNode{TlsSettings: panel.TlsSettings{ServerName: "a.test", Dest: "b.test"}}
	host, port, sni, ok = realityTarget(&panel.NodeInfo{Security: panel.Reality, AnyTls: a, Common: &a.CommonNode})
	if !ok || host != "b.test" || port != "443" || sni != "a.test" {
		t.Fatalf("anytls REALITY: %s %s %s %v", host, port, sni, ok)
	}
	if _, _, _, ok := realityTarget(&panel.NodeInfo{Security: panel.Tls, AnyTls: a, Common: &a.CommonNode}); ok {
		t.Fatal("a plain TLS node has no REALITY target")
	}
}
