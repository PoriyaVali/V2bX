package node

import (
	"path/filepath"
	"testing"
)

func Test_generateSelfSslCertificate(t *testing.T) {
	// A temp dir, not the package directory: this writes a private key.
	dir := t.TempDir()
	if err := generateSelfSslCertificate("domain.com", filepath.Join(dir, "1.pem"), filepath.Join(dir, "1.key")); err != nil {
		t.Fatal(err)
	}
}
