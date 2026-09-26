package node

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSelfSignedCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := generateSelfSslCertificate("node.example", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("the pair does not load: %v", err)
	}
	key, _ := os.ReadFile(keyPath)
	if len(key) < 30 || string(key[:31]) != "-----BEGIN RSA PRIVATE KEY-----" {
		t.Fatalf("key is not labelled as the RSA key it is: %q", key[:31])
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode %v, want 0600", st.Mode().Perm())
		}
	}
}
