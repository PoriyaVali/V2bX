// Package certtest creates a private local CA and leaf fixtures for TLS tests.
package certtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/common/file"
)

type Authority struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	Roots *x509.CertPool
}

type Pair struct {
	Certificate, Key []byte
	Leaf             *x509.Certificate
}

func NewAuthority(t testing.TB) *Authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "local certificate lifecycle test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &Authority{cert: ca, key: key, Roots: roots}
}

func (a *Authority) Issue(t testing.TB, domain string, serial int64, before, after time.Time) Pair {
	return a.IssueNames(t, []string{domain}, serial, before, after)
}

func (a *Authority) IssueNames(t testing.TB, domains []string, serial int64, before, after time.Time) Pair {
	return a.IssueWithUsage(t, domains, serial, before, after, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func (a *Authority) IssueWithUsage(t testing.TB, domains []string, serial int64, before, after time.Time, usage []x509.ExtKeyUsage) Pair {
	return a.issue(t, domains, serial, before, after, usage, nil)
}

func (a *Authority) IssueWithUnknownUsage(t testing.TB, domains []string, serial int64, before, after time.Time) Pair {
	return a.issue(t, domains, serial, before, after, nil, []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 1}})
}

func (a *Authority) issue(t testing.TB, domains []string, serial int64, before, after time.Time, usage []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier) Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: domains,
		NotBefore: before, NotAfter: after, ExtKeyUsage: usage, UnknownExtKeyUsage: unknown, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Pair{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), Leaf: leaf}
}

func Write(t testing.TB, certPath, keyPath string, p Pair) {
	t.Helper()
	if certPath == keyPath {
		if err := file.WriteAtomic(certPath, append(append([]byte{}, p.Certificate...), p.Key...), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := file.WriteAtomic(keyPath, p.Key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := file.WriteAtomic(certPath, p.Certificate, 0644); err != nil {
		t.Fatal(err)
	}
}
