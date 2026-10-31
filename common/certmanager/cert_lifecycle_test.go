package certmanager

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/tlscert"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/go-acme/lego/v4/certificate"
)

// A private local CA signs realistic ACME replacements. No authority, DNS
// provider or public endpoint is contacted by any lifecycle fixture.
type lifecycleCA struct {
	leaf *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newLifecycleCA(t *testing.T) *lifecycleCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "V2bX local test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &lifecycleCA{leaf: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *lifecycleCA) issue(t *testing.T, serial int64, names []string, before, after time.Time) *certificate.Resource {
	return ca.issueWithUsages(t, serial, names, before, after, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func (ca *lifecycleCA) issueWithUsages(t *testing.T, serial int64, names []string, before, after time.Time, usages []x509.ExtKeyUsage) *certificate.Resource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: before, NotAfter: after,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages,
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.leaf, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func TestCertificateServerAuthenticationUsage(t *testing.T) {
	ca, now := newLifecycleCA(t), time.Now()
	for _, row := range []struct {
		name  string
		usage []x509.ExtKeyUsage
		valid bool
	}{
		{"server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true},
		{"unrestricted", nil, true},
		{"any", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, true},
		{"client only", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			c := existingCertConfig(t)
			issued := ca.issueWithUsages(t, 9, []string{c.CertDomain}, now.Add(-time.Hour), now.Add(90*24*time.Hour), row.usage)
			if err := (&Lego{config: c}).writeCert(issued); (err == nil) != row.valid {
				t.Fatalf("TLS server certificate accepted=%v, want %v: %v", err == nil, row.valid, err)
			}
			// Simulate an existing operator-installed pair as well as a new
			// authority response. Both must enforce server authentication.
			if err := os.WriteFile(c.CertFile, issued.Certificate, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(c.KeyFile, issued.PrivateKey, 0600); err != nil {
				t.Fatal(err)
			}
			c.CertMode = "file"
			if err := Ensure(c); (err == nil) != row.valid {
				t.Fatalf("existing server certificate accepted=%v, want %v: %v", err == nil, row.valid, err)
			}
			if !row.valid {
				c.CertMode = "http"
				issuer := &lifecycleIssuer{results: []*certificate.Resource{ca.issue(t, 10, []string{c.CertDomain}, now.Add(-time.Hour), now.Add(90*24*time.Hour))}}
				l, err := NewLegoWithIssuer(c, issuer)
				if err != nil {
					t.Fatal(err)
				}
				if err := l.CreateCert(); err != nil {
					t.Fatal(err)
				}
				if len(issuer.requests) != 1 {
					t.Fatal("managed mode reused a certificate without server authentication usage")
				}
			}
		})
	}
}

func TestCertificateCandidateRejectsWrongNameAndInvalidTimeBeforeInstall(t *testing.T) {
	ca := newLifecycleCA(t)
	now := time.Now()
	for _, row := range []struct {
		name   string
		names  []string
		before time.Time
		after  time.Time
	}{
		{"wrong SAN", []string{"other.example.test"}, now.Add(-time.Hour), now.AddDate(0, 3, 0)},
		{"expired", []string{"node.example.test"}, now.AddDate(0, -3, 0), now.Add(-time.Minute)},
		{"not yet valid", []string{"node.example.test"}, now.Add(time.Hour), now.AddDate(0, 3, 0)},
	} {
		t.Run(row.name, func(t *testing.T) {
			config := existingCertConfig(t)
			beforeCert, _ := os.ReadFile(config.CertFile)
			beforeKey, _ := os.ReadFile(config.KeyFile)
			l := &Lego{config: config}
			if err := l.writeCert(ca.issue(t, 2, row.names, row.before, row.after)); err == nil {
				t.Fatal("invalid ACME replacement was accepted")
			}
			afterCert, _ := os.ReadFile(config.CertFile)
			afterKey, _ := os.ReadFile(config.KeyFile)
			if !bytes.Equal(beforeCert, afterCert) || !bytes.Equal(beforeKey, afterKey) {
				t.Fatal("rejected replacement changed the active certificate or key")
			}
		})
	}
}

func TestSelfCertificateCoversIPDomains(t *testing.T) {
	for _, domain := range []string{"127.0.0.1", "2001:db8::1"} {
		t.Run(domain, func(t *testing.T) {
			dir := t.TempDir()
			c := &conf.CertConfig{CertMode: "self", CertDomain: domain, CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}

			if err := Ensure(c); err != nil {
				t.Fatal(err)
			}
			if err := ValidCertificatePair(c); err != nil {
				t.Fatal("generated self certificate does not cover its configured IP:", err)
			}
		})
	}
}

func TestManagedCombinedPEMRemainsACompletePair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "combined.pem")
	ca := newLifecycleCA(t)
	l := &Lego{config: &conf.CertConfig{CertDomain: "node.example.test", CertFile: path, KeyFile: path}}
	if err := l.writeCert(ca.issue(t, 2, []string{"node.example.test"}, time.Now().Add(-time.Hour), time.Now().AddDate(0, 3, 0))); err != nil {
		t.Fatal(err)
	}
	if err := ValidCertificatePair(l.config); err != nil {
		t.Fatal("managed write destroyed its combined certificate and private key:", err)
	}
}

func TestManagedCombinedPEMWindowsCaseAliasesRemainACompletePair(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case-insensitive filesystem regression")
	}
	path := filepath.Join(t.TempDir(), "combined.pem")
	ca := newLifecycleCA(t)
	l := &Lego{config: &conf.CertConfig{CertDomain: "node.example.test", CertFile: path, KeyFile: strings.ToUpper(path)}}
	if err := l.writeCert(ca.issue(t, 2, []string{"node.example.test"}, time.Now().Add(-time.Hour), time.Now().AddDate(0, 3, 0))); err != nil {
		t.Fatal(err)
	}
	if err := ValidCertificatePair(l.config); err != nil {
		t.Fatal("case aliases of a combined PEM lost the private key:", err)
	}
}

type lifecycleIssuer struct {
	mu       sync.Mutex
	requests []certificate.ObtainRequest
	results  []*certificate.Resource
	errors   []error
	check    func()
}

func (i *lifecycleIssuer) Obtain(request certificate.ObtainRequest) (*certificate.Resource, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.check != nil {
		i.check()
	}
	i.requests = append(i.requests, request)
	n := len(i.requests) - 1
	if n >= len(i.results) {
		return nil, errors.New("unexpected ACME request")
	}
	if n < len(i.errors) && i.errors[n] != nil {
		return nil, i.errors[n]
	}
	return i.results[n], nil
}

func lifecycleTLSProbe(t *testing.T, c *conf.CertConfig, ca *lifecycleCA) func(int64) {
	t.Helper()
	loader, err := tlscert.New(c.CertFile, c.KeyFile, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{GetCertificate: loader.GetCertificate, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.pem) {
		t.Fatal("invalid local CA fixture")
	}
	transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: c.CertDomain}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	return func(want int64) {
		t.Helper()
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal("local verified TLS handshake:", err)
		}
		response.Body.Close()
		if got := response.TLS.PeerCertificates[0].SerialNumber.Int64(); got != want {
			t.Fatalf("served certificate serial %d, want %d", got, want)
		}
	}
}

func TestManagedIssuanceRenewalAndFailureServeVerifiedTLS(t *testing.T) {
	for _, mode := range []string{"http", "dns"} {
		t.Run(mode, func(t *testing.T) {
			ca, now := newLifecycleCA(t), time.Now()
			dir := t.TempDir()
			c := &conf.CertConfig{CertMode: mode, CertDomain: "node.example.test", CertFile: filepath.Join(dir, "fullchain.pem"), KeyFile: filepath.Join(dir, "private.key"), Provider: "test-provider", DNSEnv: map[string]string{"V2BX_LIFECYCLE_DNS_ACCOUNT": "test-scope"}}
			t.Setenv("V2BX_LIFECYCLE_DNS_ACCOUNT", "original")
			first := ca.issue(t, 2, []string{c.CertDomain, "obsolete.example.test"}, now.Add(-time.Hour), now.Add(20*24*time.Hour))
			next := ca.issue(t, 3, []string{c.CertDomain}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
			failure := errors.New("local authority temporarily unavailable")
			issuer := &lifecycleIssuer{results: []*certificate.Resource{first, nil, next}, errors: []error{nil, failure, nil}, check: func() {
				if os.Getenv("V2BX_LIFECYCLE_DNS_ACCOUNT") != "test-scope" {
					t.Error("request escaped its provider credential scope")
				}
			}}
			l, err := NewLegoWithIssuer(c, issuer)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.CreateCert(); err != nil {
				t.Fatal(err)
			}
			probe := lifecycleTLSProbe(t, c, ca)
			probe(2)
			beforeCert, _ := os.ReadFile(c.CertFile)
			beforeKey, _ := os.ReadFile(c.KeyFile)
			if err := l.RenewCert(); !errors.Is(err, failure) {
				t.Fatal("renewal failure not reported:", err)
			}
			failedCert, _ := os.ReadFile(c.CertFile)
			failedKey, _ := os.ReadFile(c.KeyFile)
			if !bytes.Equal(beforeCert, failedCert) || !bytes.Equal(beforeKey, failedKey) {
				t.Fatal("failed renewal damaged active pair")
			}
			probe(2)
			if err := l.RenewCert(); err != nil {
				t.Fatal("renewal retry failed:", err)
			}
			probe(3)
			afterCert, _ := os.ReadFile(c.CertFile)
			if bytes.Equal(beforeCert, afterCert) {
				t.Fatal("successful renewal did not change certificate bytes")
			}
			if err := l.RenewCert(); err != nil {
				t.Fatal(err)
			}
			if err := l.CreateCert(); err != nil {
				t.Fatal(err)
			}
			if len(issuer.requests) != 3 {
				t.Fatalf("healthy certificate reissued: %d requests", len(issuer.requests))
			}
			for _, request := range issuer.requests {
				if !reflect.DeepEqual(request.Domains, []string{c.CertDomain}) || !request.Bundle {
					t.Fatalf("renewal inherited unrelated historical SANs: %+v", request)
				}
			}
			if os.Getenv("V2BX_LIFECYCLE_DNS_ACCOUNT") != "original" {
				t.Fatal("provider credential did not restore its previous environment")
			}
		})
	}
}

func TestExplicitDNSWildcardAndInvalidACMEIdentities(t *testing.T) {
	dir := t.TempDir()
	config := &conf.CertConfig{CertMode: "dns", Provider: "test-provider", CertDomain: "*.EXAMPLE.test.", CertFile: filepath.Join(dir, "cert"), KeyFile: filepath.Join(dir, "key")}
	ca := newLifecycleCA(t)
	issuer := &lifecycleIssuer{results: []*certificate.Resource{ca.issue(t, 8, []string{"*.example.test"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))}}
	l, err := NewLegoWithIssuer(config, issuer)
	if err != nil {
		t.Fatal("explicit DNS wildcard rejected:", err)
	}
	if err := l.CreateCert(); err != nil {
		t.Fatal(err)
	}
	if issuer.requests[0].Domains[0] != "*.example.test" {
		t.Fatal("wildcard identity not canonicalized")
	}
	config.CertMode = "http"
	if _, err := NewLego(config); err == nil {
		t.Fatal("HTTP01 accepted wildcard identity")
	}
	for _, domain := range []string{"127.0.0.1", "2001:db8::1", "https://example.test", "example.test:443", "../example.test"} {
		config.CertDomain = domain
		if _, err := NewLego(config); err == nil {
			t.Errorf("invalid automatic certificate identity accepted: %s", domain)
		}
	}
}

func TestManagedModeReplacesSelfSignedWithoutWaitingForItsExpiry(t *testing.T) {
	for _, mode := range []string{"http", "dns"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			c := &conf.CertConfig{CertMode: mode, CertDomain: "node.example.test", CertFile: filepath.Join(dir, "cert"), KeyFile: filepath.Join(dir, "key"), Provider: "test-provider"}
			if err := GenerateSelf(c.CertDomain, c.CertFile, c.KeyFile); err != nil {
				t.Fatal(err)
			}
			ca := newLifecycleCA(t)
			issuer := &lifecycleIssuer{results: []*certificate.Resource{ca.issue(t, 4, []string{c.CertDomain}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))}}
			l, err := NewLegoWithIssuer(c, issuer)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.CreateCert(); err != nil {
				t.Fatal(err)
			}
			if len(issuer.requests) != 1 {
				t.Fatal("managed mode kept a thirty-year self-signed certificate")
			}
			if err := validManagedCertificatePair(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedRenewalRepairsMissingPrivateKeyBeforeExpiry(t *testing.T) {
	c := existingCertConfig(t)
	if err := os.Remove(c.KeyFile); err != nil {
		t.Fatal(err)
	}
	ca := newLifecycleCA(t)
	issuer := &lifecycleIssuer{results: []*certificate.Resource{ca.issue(t, 5, []string{c.CertDomain}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))}}
	l, err := NewLegoWithIssuer(c, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RenewCert(); err != nil {
		t.Fatal(err)
	}
	if len(issuer.requests) != 1 || ValidCertificatePair(c) != nil {
		t.Fatal("unexpired certificate with missing key was not repaired")
	}
}

func TestSharedPathsIssueOnlyOnceAndSelfEnsureStaysMatched(t *testing.T) {
	ca, now := newLifecycleCA(t), time.Now()
	dir := t.TempDir()
	c := &conf.CertConfig{CertMode: "http", CertDomain: "node.example.test", CertFile: filepath.Join(dir, "cert"), KeyFile: filepath.Join(dir, "key")}
	issuer := &lifecycleIssuer{results: []*certificate.Resource{ca.issue(t, 6, []string{c.CertDomain}, now.Add(-time.Hour), now.Add(90*24*time.Hour))}}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			l, err := NewLegoWithIssuer(c, issuer)
			if err == nil {
				err = l.CreateCert()
			}
			if err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if len(issuer.requests) != 1 || ValidCertificatePair(c) != nil {
		t.Fatal("shared paths issued repeatedly or left a mismatched pair")
	}
	c.CertMode = "self"
	if err := os.Remove(c.CertFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(c.KeyFile); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			if err := Ensure(c); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if err := ValidCertificatePair(c); err != nil {
		t.Fatal("parallel self creation left mismatched pair:", err)
	}
}

func TestRenewalWindowUsesExactTimeAndSelfRenews(t *testing.T) {
	now := time.Now()
	for _, row := range []struct {
		remaining time.Duration
		due       bool
	}{{renewalWindow + time.Second, false}, {renewalWindow, true}, {renewalWindow - time.Second, true}, {-time.Second, true}} {
		if got := certificateDueAt(&x509.Certificate{NotAfter: now.Add(row.remaining)}, now); got != row.due {
			t.Fatalf("remaining %s: due=%v", row.remaining, got)
		}
	}
	c := existingCertConfig(t)
	c.CertMode = "self"
	ca := newLifecycleCA(t)
	if err := (&Lego{config: c}).writeCert(ca.issue(t, 7, []string{c.CertDomain}, now.Add(-time.Hour), now.Add(24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(c.CertFile)
	if err := Renew(c); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(c.CertFile)
	if bytes.Equal(before, after) || ValidCertificatePair(c) != nil {
		t.Fatal("self maintenance did not replace a due certificate")
	}
}

// A busy port 80 is named as the http-01 challenge's need, not left as a bare
// "address already in use".
func TestChallengePortErrorNamesPort80(t *testing.T) {
	err := explainChallengePort(errors.New("acme: error presenting token: could not start HTTP server for challenge: listen tcp :80: bind: address already in use"))
	if err == nil || !strings.Contains(err.Error(), "needs TCP port 80") || !strings.Contains(err.Error(), "CertMode dns") {
		t.Fatalf("busy port 80 not explained: %v", err)
	}
	other := errors.New("acme: urn:ietf:params:acme:error:rateLimited")
	if explainChallengePort(other) != other {
		t.Fatal("an unrelated failure was rewritten")
	}
}
