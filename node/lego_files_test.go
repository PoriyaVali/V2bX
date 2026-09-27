package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/go-acme/lego/v4/certificate"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// The issued certificate's private key is readable by its owner only - also
// when it replaces a key file written world-readable by an older version.
func TestWriteCert_KeyIsPrivate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "cert.key")
	if err := os.WriteFile(keyPath, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	l := &Lego{config: &conf.CertConfig{CertFile: filepath.Join(dir, "cert.pem"), KeyFile: keyPath}}
	if err := l.writeCert(&certificate.Resource{Certificate: []byte("c"), PrivateKey: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, keyPath); m != 0600 {
		t.Fatalf("private key mode = %o, want 600", m)
	}
}

// The ACME account file holds the account's private key: 0600, and it can be
// read back.
func TestLegoUser_SaveIsPrivateAndLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user", "user-a@b.c.json")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u := &User{Email: "a@b.c", key: key}
	if err := u.Save(path); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, path); m != 0600 {
		t.Fatalf("account file mode = %o, want 600", m)
	}
	var back User
	if err := back.Load(path); err != nil {
		t.Fatal(err)
	}
	if back.Email != "a@b.c" || back.key == nil {
		t.Fatalf("loaded %+v", back)
	}
}

// A damaged account file is an error, not a nil-pointer panic.
func TestLegoUser_LoadDamagedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "u.json")
	os.WriteFile(path, []byte(`{"Email":"a@b.c","Key":"not pem"}`), 0600)
	var u User
	if err := u.Load(path); err == nil {
		t.Fatal("a key that is not PEM must fail to load")
	}
}

// A certificate that cannot be parsed is reported, not taken as "not due".
func TestRenewCert_DamagedCertificateIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.pem")
	os.WriteFile(path, []byte("garbage"), 0644)
	l := &Lego{config: &conf.CertConfig{CertFile: path}}
	if err := l.RenewCert(); err == nil {
		t.Fatal("renewal said nothing about a certificate it could not read")
	}
}
