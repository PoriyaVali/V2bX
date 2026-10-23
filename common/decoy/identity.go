package decoy

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"strings"
)

// Identity makes nodes serving one owned certificate name share the same site.
// Only trusted configuration/certificate metadata participates; request Host,
// forwarded headers and unauthenticated SNI never select files or content.
func Identity(domain, certFile, tag string) string {
	if domain != "" {
		return "domain:" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	}
	if f, err := os.Open(certFile); err == nil {
		data, readErr := io.ReadAll(io.LimitReader(f, 64<<10))
		_ = f.Close()
		if readErr == nil {
			if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
				if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
					if len(leaf.DNSNames) > 0 {
						return "domain:" + strings.ToLower(leaf.DNSNames[0])
					}
					if len(leaf.IPAddresses) > 0 {
						return "certificate-ip:" + leaf.IPAddresses[0].String()
					}
				}
			}
		}
	}
	return Seed(tag)
}
