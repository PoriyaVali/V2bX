package node

import (
	"log"
	"os"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
)

var l *Lego

func init() {
	var err error
	l, err = NewLego(&conf.CertConfig{
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
		log.Println(err)
		os.Exit(1)
	}
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
	err := l.CreateCert()
	if err != nil {
		t.Error(err)
	}
}

func TestLego_RenewCert(t *testing.T) {
	requireACME(t)
	log.Println(l.RenewCert())
}
