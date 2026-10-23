package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/file"
)

func testPair(t testing.TB, serial int64) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"node.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})
}

func TestLiveTLSKeepsLastPairDuringReplacementAndRotatesWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	first, firstKey := testPair(t, 1)
	second, secondKey := testPair(t, 2)
	write := func(path string, data []byte) {
		t.Helper()
		if err := file.WriteAtomic(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(certPath, first)
	write(keyPath, firstKey)
	loader, err := New(certPath, keyPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	server.TLS = &tls.Config{GetCertificate: loader.GetCertificate, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(first)
	roots.AppendCertsFromPEM(second)
	transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "node.example.test", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	probe := func(want int64) {
		t.Helper()
		r, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if got := r.TLS.PeerCertificates[0].SerialNumber.Int64(); got != want {
			t.Fatalf("peer serial=%d, want %d", got, want)
		}
	}
	probe(1)
	write(keyPath, secondKey) // A renewal installs two separate files.
	probe(1)                  // Mismatched candidate cannot replace the active pair.
	write(certPath, second)
	probe(2)
	write(certPath, []byte("incomplete certificate"))
	probe(2)
	write(certPath, first)
	write(keyPath, firstKey)
	probe(1)
}

func TestLoaderConcurrentSelectionAndRotation(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	cert, key := testPair(t, 1)
	if err := file.WriteAtomic(c, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := file.WriteAtomic(k, key, 0600); err != nil {
		t.Fatal(err)
	}
	l, err := New(c, k, 0)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			for j := 0; j < 30; j++ {
				pair, err := l.GetCertificate(nil)
				if err != nil || pair == nil {
					t.Error("lost active certificate")
				}
			}
		})
	}
	for i := 0; i < 10; i++ {
		if err := file.WriteAtomic(c, cert, 0600); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
}

func TestDomainRejectsPathsIPsAndInvalidLabels(t *testing.T) {
	for _, value := range []string{"../a.test", "https://a.test", "a.test:443", "192.0.2.1", "::1", "*.a.test", "-bad.test", "a..test", "a.test/secret"} {
		if _, err := Domain(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	if domain, err := Domain("NODE.Example.TEST."); err != nil || domain != "node.example.test" {
		t.Fatalf("normalize hostname: %q / %v", domain, err)
	}
}

func BenchmarkCertificateSelection(b *testing.B) {
	dir := b.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	cert, key := testPair(b, 1)
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		b.Fatal(err)
	}
	loader, err := New(certPath, keyPath, time.Minute)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("disk_each_handshake", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := loader.GetCertificate(nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}
