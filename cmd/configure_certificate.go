package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

// SNI describes the client's TLS handshake (or a REALITY target), not a domain
// the operator controls. Never send it to ACME as a fallback for missing host.
func panelCertificateDomain(info *panel.NodeInfo) string {
	if info == nil || info.Common == nil {
		return ""
	}
	return strings.TrimSpace(info.Common.Host)
}

// Only used for display. This value must never select a certificate domain.
func panelTLSName(info *panel.NodeInfo) string {
	if info.AnyTls != nil {
		if info.Security == panel.Reality {
			return info.AnyTls.TlsSettings.ServerName
		}
		if name := info.AnyTls.CommonNode.ServerName; name != "" {
			return name
		}
		return info.AnyTls.TlsSettings.ServerName
	}
	if info.VAllss != nil {
		if name := info.VAllss.TlsSettings.ServerName; name != "" {
			return name
		}
		if name := info.VAllss.ServerName; name != "" {
			return name
		}
	}
	if info.Common != nil {
		return info.Common.ServerName
	}
	return ""
}

func sameSetupDomain(a, b string) bool {
	// Also handles IP SANs for file certificates and canonicalizes IDNs.
	x, ex := setupCertificateDomain(a, "file")
	y, ey := setupCertificateDomain(b, "file")
	return ex == nil && ey == nil && x == y
}

func retargetSetupCertificate(cert conf.CertConfig, domain, output string) conf.CertConfig {
	if cert.CertMode != "file" && (!sameSetupDomain(cert.CertDomain, domain) || cert.CertFile == "" || cert.KeyFile == "") {
		// Existing paths can be shared with other nodes. A domain correction
		// must not replace those nodes' active certificates on the next start.
		cert.CertFile = filepath.Join(filepath.Dir(output), "certs", domain, "fullchain.pem")
		cert.KeyFile = filepath.Join(filepath.Dir(output), "certs", domain, "private.key")
	}
	cert.CertDomain = domain
	return cert
}

func applySetupCertificateFlags(o *configureOptions) {
	if o.existingCert == nil {
		return
	}
	cert := *o.existingCert
	if o.certificateFlags["cert-mode"] {
		cert.CertMode = o.certMode
		if cert.CertMode == "auto" {
			cert.CertMode = "http"
			if o.provider != "" {
				cert.CertMode = "dns"
			}
		}
	} else if o.certificateFlags["dns-provider"] {
		cert.CertMode = "dns"
	}
	if o.existingCert.CertMode == "file" && cert.CertMode != "file" {
		cert.CertFile, cert.KeyFile = "", ""
	}
	for _, field := range []struct {
		flag, value string
		target      *string
	}{
		{"cert-file", o.certFile, &cert.CertFile}, {"key-file", o.keyPath, &cert.KeyFile},
		{"dns-provider", o.provider, &cert.Provider}, {"acme-email", o.email, &cert.Email},
		{"http-webroot", o.webroot, &cert.HTTPWebRoot},
	} {
		if o.certificateFlags[field.flag] {
			*field.target = field.value
		}
	}
	// --dns-env-file is parsed and applied by the builder. Other saved fields
	// remain intact: changing only email must not discard DNS renewal secrets.
	o.existingCert, o.certMode, o.provider = &cert, cert.CertMode, cert.Provider
}

func chooseSetupCertificateDomain(p setupPrompter, o configureOptions, info *panel.NodeInfo) (string, error) {
	if info.Security != panel.Tls || info.Type == "trusttunnel" {
		return "", nil
	}
	domain := o.certDomain
	if domain == "" {
		host, hostErr := setupCertificateDomain(panelCertificateDomain(info), o.certMode)
		var saved string
		if o.existingCert != nil {
			saved, _ = setupCertificateDomain(o.existingCert.CertDomain, o.certMode)
		}
		domain = host
		if saved != "" {
			domain = saved
		}
		if hostErr == nil && saved != "" && saved != host {
			// A prior wizard may have saved SNI as CertDomain. Do not silently
			// keep that mistake, or overwrite an intentional origin/CDN setup.
			fmt.Fprintf(p.out, "Certificate domain conflict | دامنه نود با گواهی ذخیره‌شده متفاوت است:\n  1. Node host | دامنه نود: %s\n  2. Saved certificate domain | دامنه گواهی قبلی: %s\n  3. Enter another domain | ورود دامنه دیگر\n", host, saved)
			choice, err := p.choice("Certificate domain | انتخاب دامنه گواهی", []string{host, saved, "manual"}, 0)
			if err != nil {
				return "", err
			}
			domain = []string{host, saved, ""}[choice]
		} else if hostErr != nil && saved != "" && sameSetupDomain(saved, panelTLSName(info)) {
			// Older panel APIs omit host. A saved name equal to SNI may be the
			// earlier wizard's bad guess; require a conscious choice to reuse it.
			fmt.Fprintf(p.out, "Panel has no usable certificate host; saved domain matches SNI | دامنه نود مشخص نیست؛ دامنه قبلی همان SNI است:\n  1. Keep saved domain you control | حفظ دامنه قبلی تحت کنترل شما: %s\n  2. Enter another domain | ورود دامنه دیگر\n", saved)
			choice, err := p.choice("Certificate domain | انتخاب دامنه گواهی", []string{saved, "manual"}, 0)
			if err != nil {
				return "", err
			}
			domain = []string{saved, ""}[choice]
		}
	}
	for {
		if valid, err := setupCertificateDomain(domain, o.certMode); err == nil {
			return valid, nil
		}
		fmt.Fprintln(p.out, "A valid certificate domain is required; SNI is not used for issuance | دامنه معتبر تحت کنترل شما لازم است؛ SNI مبنای صدور نیست")
		var err error
		domain, err = p.ask("Certificate domain (n to cancel) | دامنه گواهی، لغو با n", "")
		if err != nil {
			return "", err
		}
		if strings.EqualFold(domain, "n") {
			return "", fmt.Errorf("wizard cancelled; existing configuration was kept")
		}
	}
}
