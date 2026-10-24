package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/registration"
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
	certPath := filepath.Join(dir, "cert.pem")
	if err := GenerateSelf("node.example.test", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(certPath)
	keyPEM, _ := os.ReadFile(keyPath)
	if err := os.WriteFile(keyPath, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	l := &Lego{config: &conf.CertConfig{CertFile: certPath, KeyFile: keyPath}}
	if err := l.writeCert(&certificate.Resource{Certificate: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, keyPath); runtime.GOOS != "windows" && m != 0600 {
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
	if m := mode(t, path); runtime.GOOS != "windows" && m != 0600 {
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

func TestLegoUserExistingRegistrationAndKeyAreReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u := &User{Email: "a@b.c", key: key, Registration: &registration.Resource{URI: "https://local.invalid/acme/account/1"}}
	if err := u.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		// A successful return requires no client construction or CA request:
		// the persisted registration URI and account key are sufficient.
		back, err := NewLegoUser(path, u.Email)
		if err != nil {
			t.Fatal(err)
		}
		if back.Registration == nil || back.Registration.URI != u.Registration.URI || !key.Equal(back.key) {
			t.Fatal("existing account registration or private key was replaced")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("loading an account unexpectedly rewrote persisted registration")
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
