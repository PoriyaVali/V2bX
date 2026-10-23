package tlscert

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// Domain validates a certificate hostname before using it in paths or ACME.
// IP-only certificates and wildcard DNS challenges require explicit setup.
func Domain(value string) (string, error) {
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if err != nil || net.ParseIP(name) != nil || !strings.Contains(name, ".") || len(name) > 253 {
		return "", fmt.Errorf("a DNS hostname is required for automatic certificates")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid certificate hostname")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid certificate hostname")
			}
		}
	}
	return strings.ToLower(name), nil
}
