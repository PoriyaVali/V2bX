package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/go-acme/lego/v4/certificate"
)

func existingCertConfig(t *testing.T) *conf.CertConfig {
	t.Helper()
	dir := t.TempDir()
	c := &conf.CertConfig{CertMode: "http", CertDomain: "node.example.test", CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem")}
	if err := generateSelfSslCertificate(c.CertDomain, c.CertFile, c.KeyFile); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRenewalNotDueDoesNotRegisterOrInitializeACME(t *testing.T) {
	c := existingCertConfig(t)
	l, err := NewLego(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.RenewCert(); err != nil {
			t.Fatal(err)
		}
	}
	if l.client != nil {
		t.Fatal("local expiry checks initialized a network ACME client")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(c.CertFile), "user")); !os.IsNotExist(err) {
		t.Fatal("local expiry check created an ACME account")
	}
}

func TestExistingPairMustMatchDomainKeyAndValidity(t *testing.T) {
	c := existingCertConfig(t)
	controller := &Controller{Options: &conf.Options{CertConfig: c}}
	if err := controller.requestCert(); err != nil {
		t.Fatal(err)
	}
	c.CertMode = "file"
	c.CertDomain = "other.example.test"
	if err := controller.requestCert(); err == nil {
		t.Fatal("wrong domain was accepted")
	}
	c.CertDomain = "node.example.test"
	other := existingCertConfig(t)
	key, _ := os.ReadFile(other.KeyFile)
	if err := os.WriteFile(c.KeyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := controller.requestCert(); err == nil {
		t.Fatal("mismatched certificate key was accepted")
	}
}

func TestInvalidIssuedPairDoesNotClobberExistingFiles(t *testing.T) {
	c := existingCertConfig(t)
	beforeCert, _ := os.ReadFile(c.CertFile)
	beforeKey, _ := os.ReadFile(c.KeyFile)
	l, err := NewLego(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.writeCert(&certificate.Resource{Certificate: []byte("broken"), PrivateKey: []byte("broken")}); err == nil {
		t.Fatal("invalid issued pair accepted")
	}
	afterCert, _ := os.ReadFile(c.CertFile)
	afterKey, _ := os.ReadFile(c.KeyFile)
	if string(beforeCert) != string(afterCert) || string(beforeKey) != string(afterKey) {
		t.Fatal("invalid issuance destroyed active files")
	}
}

func TestCertificateInstallFailureRestoresPreviousPrivateKey(t *testing.T) {
	current := existingCertConfig(t)
	next := existingCertConfig(t)
	before, _ := os.ReadFile(current.KeyFile)
	cert, _ := os.ReadFile(next.CertFile)
	key, _ := os.ReadFile(next.KeyFile)
	blocked := filepath.Join(t.TempDir(), "certificate-is-a-directory")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep"), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	l := &Lego{config: &conf.CertConfig{CertFile: blocked, KeyFile: current.KeyFile}}
	if err := l.writeCert(&certificate.Resource{Certificate: cert, PrivateKey: key}); err == nil {
		t.Fatal("failed certificate install accepted")
	}
	after, _ := os.ReadFile(current.KeyFile)
	if !bytes.Equal(before, after) || validCertificatePair(current) != nil {
		t.Fatal("failed install left active certificate without its private key")
	}
}

func TestDNSCredentialScopesAreSerializedAndRestoredOnErrors(t *testing.T) {
	const key = "V2BX_TEST_DNS_ACCOUNT"
	t.Setenv(key, "original")
	wantErr := errors.New("provider failed")
	var workers sync.WaitGroup
	for _, account := range []string{"one", "two", "three"} {
		workers.Go(func() {
			err := withACMEEnvironment(map[string]string{key: account}, func() error {
				if os.Getenv(key) != account {
					t.Error("DNS account mixed with another node")
				}
				return wantErr
			})
			if !errors.Is(err, wantErr) {
				t.Error("provider error lost")
			}
		})
	}
	workers.Wait()
	if os.Getenv(key) != "original" {
		t.Fatal("DNS credentials leaked into process environment")
	}
}
