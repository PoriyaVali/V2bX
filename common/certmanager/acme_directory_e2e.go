//go:build acme_e2e

package certmanager

import "os"

// In an acme_e2e build, V2BX_TEST_ACME_DIRECTORY replaces Let's Encrypt with a
// local test CA, read at every request so a test can switch between CAs. Never
// part of a release: see scripts/e2e/trusttunnel-acme.
func init() {
	acmeDirectory = func() string {
		if d := os.Getenv("V2BX_TEST_ACME_DIRECTORY"); d != "" {
			return d
		}
		return "https://localhost:1/no-test-ca-configured"
	}
}
