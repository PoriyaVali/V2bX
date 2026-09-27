package node

import (
	"log"
	"os"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
)

// testLego builds the client the live ACME tests use. It used to be built in
// init(), which registers an account with Let's Encrypt and os.Exit(1)s on
// failure - so without internet access every test in this package failed,
// including the many that never touch ACME.
func testLego(t *testing.T) *Lego {
	t.Helper()
	l, err := NewLego(&conf.CertConfig{
		CertMode:   "dns",
		Email:      "test@test.com",
		CertDomain: "test.test.com",
		Provider:   "cloudflare",
		DNSEnv: map[string]string{
			"CF_DNS_API_TOKEN": "123",
		},
		CertFile: "./cert/1.pem",
		KeyFile:  "./cert/1.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// requireACME skips unless the caller opted in. These two exercise the real
// Let's Encrypt ACME API with the placeholder Cloudflare token above, so they
// can only ever fail — and they hammer a rate-limited production endpoint while
// doing it. Opt in with V2BX_ACME_E2E=1 and a real CF_DNS_API_TOKEN.
func requireACME(t *testing.T) {
	t.Helper()
	if os.Getenv("V2BX_ACME_E2E") == "" {
		t.Skip("live ACME test: set V2BX_ACME_E2E=1 (and a real CF_DNS_API_TOKEN) to run")
	}
}

func TestLego_CreateCertByDns(t *testing.T) {
	requireACME(t)
	err := testLego(t).CreateCert()
	if err != nil {
		t.Error(err)
	}
}

func TestLego_RenewCert(t *testing.T) {
	requireACME(t)
	log.Println(testLego(t).RenewCert())
}
