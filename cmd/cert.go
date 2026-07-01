package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const certDir = "/etc/V2bX"

var certCommand = cobra.Command{
	Use:   "cert",
	Short: "Show TLS certificate expiry for all domains | نمایش انقضای گواهی دامنه‌ها",
	Run: func(_ *cobra.Command, _ []string) {
		showCerts()
	},
}

func init() {
	command.AddCommand(&certCommand)
}

type certInfo struct {
	domain   string
	notAfter time.Time
	daysLeft int
	err      error
}

func showCerts() {
	matches, _ := filepath.Glob(filepath.Join(certDir, "*.cer"))
	if len(matches) == 0 {
		fmt.Println(Warn("No certificates found | گواهی‌ای یافت نشد در ", certDir))
		fmt.Printf("  (ACME certs appear here after a node with cert mode http/dns starts)\n")
		return
	}

	infos := make([]certInfo, 0, len(matches))
	for _, path := range matches {
		ci := certInfo{domain: strings.TrimSuffix(filepath.Base(path), ".cer")}
		data, err := os.ReadFile(path)
		if err != nil {
			ci.err = err
		} else if cert, perr := parseLeafCert(data); perr != nil {
			ci.err = perr
		} else {
			ci.notAfter = cert.NotAfter
			ci.daysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
		}
		infos = append(infos, ci)
	}

	// Most urgent first (fewest days remaining, errors sink to the bottom).
	sort.Slice(infos, func(i, j int) bool {
		if (infos[i].err == nil) != (infos[j].err == nil) {
			return infos[i].err == nil
		}
		return infos[i].daysLeft < infos[j].daysLeft
	})

	fmt.Printf("%-32s %-12s %-10s %s\n", "Domain | دامنه", "Expires", "Days Left", "Status")
	fmt.Println(strings.Repeat("-", 72))
	for _, ci := range infos {
		if ci.err != nil {
			fmt.Printf("%-32s %s\n", ci.domain, Err("parse error: ", ci.err))
			continue
		}
		var status string
		switch {
		case ci.daysLeft < 0:
			status = Err("EXPIRED | منقضی")
		case ci.daysLeft <= 30:
			status = Warn("Renew soon | تمدید نزدیک")
		default:
			status = Ok("OK")
		}
		fmt.Printf("%-32s %-12s %-10d %s\n",
			ci.domain, ci.notAfter.Format("2006-01-02"), ci.daysLeft, status)
	}
	fmt.Printf("\n%sV2bX auto-renews certs when under 30 days left (checked every 6h).%s\n", yellow, plain)
}

// parseLeafCert returns the first CERTIFICATE block (the leaf) from a PEM file.
func parseLeafCert(pemData []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("no certificate block found")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		pemData = rest
	}
}
