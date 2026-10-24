// Package certmanager owns certificate validation, issuance and renewal for
// embedded cores and separately supervised endpoints.
package certmanager

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/go-acme/lego/v4/certificate"
)

const renewalWindow = 30 * 24 * time.Hour

func normalizedConfig(config *conf.CertConfig) (*conf.CertConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("certificate configuration is missing")
	}
	copy := *config
	copy.ExpandPaths()
	return &copy, nil
}

// Ensure prepares a usable certificate before a TLS listener is started.
// File mode never issues or replaces operator-owned files.
func Ensure(config *conf.CertConfig) error {
	c, err := normalizedConfig(config)
	if err != nil {
		return err
	}
	switch c.CertMode {
	case "none", "":
		return nil
	case "file":
		return ValidCertificatePair(c)
	case "http", "dns":
		l, err := NewLego(c)
		if err != nil {
			return err
		}
		return l.CreateCert()
	case "self":
		return withACMEEnvironment(nil, func() error {
			if ValidCertificatePair(c) == nil {
				return nil
			}
			return generateSelf(c.CertDomain, c.CertFile, c.KeyFile)
		})
	default:
		return fmt.Errorf("unsupported certificate mode")
	}
}

// Renew keeps managed and self-signed certificates valid. File and none modes
// do not overwrite files or contact an authority. ACME retries are safe after
// failure: only a fully validated replacement can reach the active paths.
func Renew(config *conf.CertConfig) error {
	c, err := normalizedConfig(config)
	if err != nil {
		return err
	}
	switch c.CertMode {
	case "none", "", "file":
		return nil
	case "http", "dns":
		l, err := NewLego(c)
		if err != nil {
			return err
		}
		return l.RenewCert()
	case "self":
		return withACMEEnvironment(nil, func() error {
			leaf, err := loadCertificatePair(c)
			if err == nil && !certificateDueAt(leaf, time.Now()) {
				return nil
			}
			return generateSelf(c.CertDomain, c.CertFile, c.KeyFile)
		})
	default:
		return fmt.Errorf("unsupported certificate mode")
	}
}

func ValidCertificatePair(config *conf.CertConfig) error {
	if config == nil {
		return fmt.Errorf("certificate configuration is missing")
	}
	_, err := loadCertificatePair(config)
	return err
}

func loadCertificatePair(config *conf.CertConfig) (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read certificate/key pair: %w", err)
	}
	return validateCertificatePair(pair, config.CertDomain)
}

func validateCertificatePair(pair tls.Certificate, domain string) (*x509.Certificate, error) {
	leaf := pair.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, err
		}
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate is not currently valid")
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
				break
			}
		}
		if !serverAuth {
			return nil, fmt.Errorf("certificate does not permit TLS server authentication")
		}
	}
	if domain != "" {
		if err := leaf.VerifyHostname(domain); err != nil {
			return nil, fmt.Errorf("certificate domain mismatch: %w", err)
		}
	}
	return leaf, nil
}

func selfSigned(leaf *x509.Certificate) bool {
	return bytes.Equal(leaf.RawIssuer, leaf.RawSubject) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
}

func validManagedCertificatePair(config *conf.CertConfig) error {
	leaf, err := loadCertificatePair(config)
	if err != nil {
		return err
	}
	if selfSigned(leaf) {
		return fmt.Errorf("self-signed certificate does not satisfy managed ACME mode")
	}
	return nil
}

func certificateDueAt(leaf *x509.Certificate, now time.Time) bool {
	return leaf.NotAfter.Sub(now) <= renewalWindow
}

// GenerateSelf replaces a self-signed pair under the same operation lock as
// ACME, so nodes sharing paths cannot interleave certificate and key writes.
func GenerateSelf(domain, certPath, keyPath string) error {
	return withACMEEnvironment(nil, func() error { return generateSelf(domain, certPath, keyPath) })
}

func generateSelf(domain, certPath, keyPath string) error {
	if domain == "" || certPath == "" || keyPath == "" {
		return fmt.Errorf("self certificate requires a domain and certificate/key paths")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		Version: 3, SerialNumber: serial, Subject: pkix.Name{CommonName: domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(30, 0, 0),
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{domain}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	l := &Lego{config: &conf.CertConfig{CertDomain: domain, CertFile: certPath, KeyFile: keyPath}}
	return l.writeCert(&certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	})
}
