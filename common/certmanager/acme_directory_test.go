//go:build !acme_e2e

package certmanager

import (
	"testing"

	"github.com/go-acme/lego/v4/lego"
)

// Only an acme_e2e build may point ACME anywhere but Let's Encrypt.
func TestACMEDirectoryIsLetsEncryptOutsideE2EBuilds(t *testing.T) {
	t.Setenv("V2BX_TEST_ACME_DIRECTORY", "https://localhost:1/dir")
	if got := acmeDirectory(); got != lego.LEDirectoryProduction {
		t.Fatalf("a release build would request certificates from %q", got)
	}
}
