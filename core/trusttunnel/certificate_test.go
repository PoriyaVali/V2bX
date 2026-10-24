package trusttunnel

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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

type testCertificateOperations struct {
	ensure func(*conf.CertConfig) error
	renew  func(*conf.CertConfig) error
}

func (o testCertificateOperations) Ensure(c *conf.CertConfig) error {
	if o.ensure != nil {
		return o.ensure(c)
	}
	return nil
}

func (o testCertificateOperations) Renew(c *conf.CertConfig) error {
	if o.renew != nil {
		return o.renew(c)
	}
	return nil
}

func isolatedCertificateOperations(t *testing.T) certificateOperations {
	t.Helper()
	return testCertificateOperations{ensure: func(c *conf.CertConfig) error {
		if c.CertMode == "file" {
			return nil // The real snapshot loader still validates the entire pair.
		}
		if pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err == nil {
			if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && leaf.VerifyHostname(c.CertDomain) == nil {
				return nil
			}
		}
		cert, key := endpointCertificatePEM(t, c.CertDomain, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
		return writeEndpointSource(c, cert, key)
	}}
}

func endpointCertificatePEM(t *testing.T, hostname string, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "different-cn.example.test"},
		DNSNames: []string{hostname}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func writeEndpointSource(c *conf.CertConfig, cert, key []byte) error {
	for _, path := range []string{c.CertFile, c.KeyFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(c.CertFile, cert, 0o600); err != nil {
		return err
	}
	return os.WriteFile(c.KeyFile, key, 0o600)
}

func writeEndpointHosts(t *testing.T, dir, hostname string, snapshot *certificateSnapshot) {
	t.Helper()
	raw := fmt.Sprintf("[[main_hosts]]\nhostname = %q\ncert_chain_path = %q\nprivate_key_path = %q\nallowed_sni = ['alias.example.test']\n\n[extensions]\nfuture_key = 'preserved'\n", hostname, snapshot.certPath, snapshot.keyPath)
	if err := os.WriteFile(filepath.Join(dir, "hosts.toml"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateSnapshotsKeepValidTLSAcrossPartialProvidedRotation(t *testing.T) {
	dir := t.TempDir()
	p := validConfigParams()
	p.CertType = "provided"
	p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "")
	core := &TrustTunnel{certificateOps: isolatedCertificateOperations(t)}
	c, err := core.newCertificateLifecycle(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.prepare()
	if err != nil {
		t.Fatal(err)
	}
	if initial.certPath == p.CertChainPath || initial.keyPath == p.CertKeyPath {
		t.Fatal("native TLS still points directly at externally rotated files")
	}
	writeEndpointHosts(t, dir, p.Hostname, initial)
	for _, name := range []string{"credentials.toml", "vpn.toml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("untouched "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.ReadFile(filepath.Join(dir, "hosts.toml"))
	cert, key := endpointCertificatePEM(t, p.Hostname, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if err := os.WriteFile(p.CertChainPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	publishes := 0
	publish := func(commit func() error) error { publishes++; return commit() }
	if err := c.refresh(time.Now(), publish); err == nil || publishes != 0 {
		t.Fatal("partial external rotation was published")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "hosts.toml"))
	if !bytes.Equal(before, after) {
		t.Fatal("failed validation changed active TLS settings")
	}
	if _, err := tls.LoadX509KeyPair(initial.certPath, initial.keyPath); err != nil {
		t.Fatal("old immutable snapshot was damaged:", err)
	}
	if err := os.WriteFile(p.CertKeyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.refresh(time.Now(), publish); err != nil || publishes != 1 {
		t.Fatalf("valid provided renewal was not published: %v, publishes=%d", err, publishes)
	}
	settings, host, err := certificateHostSettings(filepath.Join(dir, "hosts.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if host["cert_chain_path"] == initial.certPath || host["private_key_path"] == initial.keyPath || host["hostname"] != p.Hostname {
		t.Fatal("provided renewal did not install the new hostname-matched snapshot")
	}
	if _, err := tls.LoadX509KeyPair(host["cert_chain_path"].(string), host["private_key_path"].(string)); err != nil {
		t.Fatal("published snapshot is not a matching pair:", err)
	}
	if len(host["allowed_sni"].([]any)) != 1 || settings["extensions"].(map[string]any)["future_key"] != "preserved" {
		t.Fatal("certificate publication dropped other native TLS settings")
	}
	if err := c.refresh(time.Now(), publish); err != nil || publishes != 1 {
		t.Fatal("unchanged certificate caused another reload")
	}
	for _, name := range []string{"credentials.toml", "vpn.toml"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(raw) != "untouched "+name {
			t.Fatal("certificate renewal changed endpoint configuration or users")
		}
	}
}

func TestCertificateSnapshotsRejectInvalidExternalUpdates(t *testing.T) {
	for _, scenario := range []string{"expired", "future", "wrong hostname", "wrong key", "invalid PEM"} {
		t.Run(scenario, func(t *testing.T) {
			p := validConfigParams()
			p.CertType = "provided"
			p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "")
			core := &TrustTunnel{certificateOps: isolatedCertificateOperations(t)}
			c, err := core.newCertificateLifecycle(t.TempDir(), p)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := c.prepare()
			if err != nil {
				t.Fatal(err)
			}
			writeEndpointHosts(t, c.dir, p.Hostname, snapshot)
			hostname, before, after := p.Hostname, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
			switch scenario {
			case "expired":
				before, after = before.Add(-48*time.Hour), after.Add(-48*time.Hour)
			case "future":
				before, after = before.Add(48*time.Hour), after.Add(48*time.Hour)
			case "wrong hostname":
				hostname = "unrelated.example.test"
			}
			cert, key := endpointCertificatePEM(t, hostname, before, after)
			if scenario == "wrong key" {
				_, key = endpointCertificatePEM(t, hostname, before, after)
			}
			if scenario == "invalid PEM" {
				cert = []byte("broken certificate")
			}
			if err := writeEndpointSource(c.config, cert, key); err != nil {
				t.Fatal(err)
			}
			if err := c.refresh(time.Now(), func(func() error) error { t.Fatal("invalid certificate published"); return nil }); err == nil {
				t.Fatal("invalid external update accepted")
			}
			if _, err := tls.LoadX509KeyPair(snapshot.certPath, snapshot.keyPath); err != nil {
				t.Fatal("invalid external update damaged active snapshot")
			}
		})
	}
}

func TestManagedCertificateRenewalPublishesWithoutNativeWizard(t *testing.T) {
	p := validConfigParams()
	p.CertType, p.AcmeEmail = "letsencrypt", "admin@example.test"
	renewals := 0
	core := &TrustTunnel{certificateOps: testCertificateOperations{
		ensure: isolatedCertificateOperations(t).Ensure,
		renew: func(config *conf.CertConfig) error {
			renewals++
			cert, key := endpointCertificatePEM(t, config.CertDomain, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
			return writeEndpointSource(config, cert, key)
		},
	}}
	c, err := core.newCertificateLifecycle(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	if c.config.CertMode != "http" || c.config.Email != p.AcmeEmail || c.config.AccountDir == "" {
		t.Fatal("Let's Encrypt was not routed to persistent shared HTTP-01 management")
	}
	initial, err := c.prepare()
	if err != nil {
		t.Fatal(err)
	}
	writeEndpointHosts(t, c.dir, p.Hostname, initial)
	publishes := 0
	publish := func(commit func() error) error { publishes++; return commit() }
	now := time.Now()
	if err := c.refresh(now, publish); err != nil || renewals != 1 || publishes != 1 {
		t.Fatalf("renewal was not published: %v, renewals=%d, publishes=%d", err, renewals, publishes)
	}
	if err := c.refresh(now.Add(time.Minute), publish); err != nil || renewals != 1 || publishes != 1 {
		t.Fatal("unchanged managed certificate repeated ACME work")
	}
	if err := c.refresh(now.Add(certificateRenewInterval), publish); err != nil || renewals != 2 || publishes != 2 {
		t.Fatal("scheduled renewal check was not repeated")
	}
}

func TestManagedCertificateRenewalFailureRetainsSnapshotAndRetries(t *testing.T) {
	p := validConfigParams()
	renewals := 0
	core := &TrustTunnel{certificateOps: testCertificateOperations{
		ensure: isolatedCertificateOperations(t).Ensure,
		renew:  func(*conf.CertConfig) error { renewals++; return errors.New("isolated ACME unavailable") },
	}}
	c, err := core.newCertificateLifecycle(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := c.prepare()
	if err != nil {
		t.Fatal(err)
	}
	writeEndpointHosts(t, c.dir, p.Hostname, snapshot)
	before, _ := os.ReadFile(filepath.Join(c.dir, "hosts.toml"))
	publish := func(func() error) error { t.Fatal("failed renewal published settings"); return nil }
	now := time.Now()
	if err := c.refresh(now, publish); err == nil || renewals != 1 {
		t.Fatal("renewal failure was swallowed")
	}
	if err := c.refresh(now.Add(time.Minute), publish); err != nil || renewals != 1 {
		t.Fatal("failed renewal caused a tight retry loop")
	}
	if err := c.refresh(now.Add(certificateRetryInterval), publish); err == nil || renewals != 2 {
		t.Fatal("failed renewal was not retried")
	}
	after, _ := os.ReadFile(filepath.Join(c.dir, "hosts.toml"))
	if !bytes.Equal(before, after) {
		t.Fatal("failed renewal changed active settings")
	}
}

func TestCertificatePublicationRetriesFailedReload(t *testing.T) {
	p := validConfigParams()
	p.CertType = "provided"
	p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "")
	core := &TrustTunnel{certificateOps: isolatedCertificateOperations(t)}
	c, err := core.newCertificateLifecycle(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.prepare()
	if err != nil {
		t.Fatal(err)
	}
	writeEndpointHosts(t, c.dir, p.Hostname, initial)
	cert, key := endpointCertificatePEM(t, p.Hostname, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if err := writeEndpointSource(c.config, cert, key); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("isolated signal failed")
	if err := c.refresh(time.Now(), func(commit func() error) error {
		if err := commit(); err != nil {
			return err
		}
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatal("reload failure was swallowed")
	}
	publishes := 0
	if err := c.refresh(time.Now(), func(commit func() error) error { publishes++; return commit() }); err != nil || publishes != 1 {
		t.Fatal("matching hosts paths hid a previously failed reload")
	}
}

func TestSharedSelfCertificateRenewsAndReusesLocalPair(t *testing.T) {
	p := validConfigParams()
	core := &TrustTunnel{}
	c, err := core.newCertificateLifecycle(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := endpointCertificatePEM(t, p.Hostname, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := writeEndpointSource(c.config, cert, key); err != nil {
		t.Fatal(err)
	}
	initial, err := c.prepare()
	if err != nil {
		t.Fatal(err)
	}
	writeEndpointHosts(t, c.dir, p.Hostname, initial)
	if err := c.refresh(time.Now(), func(commit func() error) error { return commit() }); err != nil {
		t.Fatal(err)
	}
	_, host, err := certificateHostSettings(filepath.Join(c.dir, "hosts.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if host["cert_chain_path"] == initial.certPath {
		t.Fatal("shared self-certificate manager did not rotate a near-expiry pair")
	}
	renewed, err := c.prepare()
	if err != nil || renewed.certPath != host["cert_chain_path"] {
		t.Fatal("healthy managed pair was reissued instead of reused")
	}
}

func TestCertificateSourceIsolationAndStoppedMaintenance(t *testing.T) {
	dir := t.TempDir()
	p := validConfigParams()
	core := &TrustTunnel{certificateOps: testCertificateOperations{ensure: func(*conf.CertConfig) error { t.Fatal("stopped certificate loop performed work"); return nil }}}
	first, err := core.newCertificateLifecycle(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*panel.TrustTunnelNode){
		func(p *panel.TrustTunnelNode) { p.Hostname = "replacement.example.test" },
		func(p *panel.TrustTunnelNode) { p.AcmeEmail = "replacement@example.test" },
		func(p *panel.TrustTunnelNode) { p.CertType = "letsencrypt" },
	} {
		copy := *p
		change(&copy)
		next, err := core.newCertificateLifecycle(dir, &copy)
		if err != nil || next.config.CertFile == first.config.CertFile {
			t.Fatal("changed certificate ownership shares an old in-flight source")
		}
	}
	stop := make(chan struct{})
	close(stop)
	first.run(stop, func(func() error) error { t.Fatal("stopped certificate loop published settings"); return nil })
}

func TestConcurrentCertificateSnapshotsShareCompleteVersion(t *testing.T) {
	p := validConfigParams()
	p.CertType = "provided"
	p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "")
	core := &TrustTunnel{certificateOps: isolatedCertificateOperations(t)}
	c, err := core.newCertificateLifecycle(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			snapshot, err := c.snapshot(time.Now())
			if err == nil {
				_, err = tls.LoadX509KeyPair(snapshot.certPath, snapshot.keyPath)
			}
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("overlapping lifecycle preparation failed:", err)
		}
	}
}
