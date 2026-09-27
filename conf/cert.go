package conf

import "strings"

type CertConfig struct {
	CertMode         string            `json:"CertMode"` // none, file, http, dns
	RejectUnknownSni bool              `json:"RejectUnknownSni"`
	CertDomain       string            `json:"CertDomain"`
	CertFile         string            `json:"CertFile"`
	KeyFile          string            `json:"KeyFile"`
	Provider         string            `json:"Provider"` // alidns, cloudflare, gandi, godaddy....
	Email            string            `json:"Email"`
	DNSEnv           map[string]string `json:"DNSEnv"`
}

func NewCertConfig() *CertConfig {
	return &CertConfig{
		CertMode: "none",
	}
}

// ExpandPaths fills {domain} and {email} in CertFile and KeyFile.
//
// The ACME code used to fill them in only when it wrote the files, while
// everything that reads them - the "already have a certificate?" check, the
// renewal, and the cores that serve it - used the path as written: a new
// certificate was requested on every start and no core could load it.
func (c *CertConfig) ExpandPaths() {
	r := strings.NewReplacer("{domain}", c.CertDomain, "{email}", c.Email)
	c.CertFile = r.Replace(c.CertFile)
	c.KeyFile = r.Replace(c.KeyFile)
}
