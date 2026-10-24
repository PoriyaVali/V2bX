package trusttunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/pelletier/go-toml/v2"
)

// ACME issuance may need several network round trips and challenge polls, but
// a stalled wizard must not block V2bX startup or a node update indefinitely.
const wizardTimeout = 5 * time.Minute

// generateConfig delegates the native configuration format to the wizard that
// ships with the endpoint. TrustTunnel uses the panel's own certificate fields;
// generic CertConfig modes cannot express its certificate lifecycle.
func (t *TrustTunnel) generateConfig(dir string, p *panel.TrustTunnelNode, metricsPort int, opts *conf.Options) error {
	if p == nil {
		return fmt.Errorf("missing TrustTunnel parameters")
	}
	if !validEndpointHostname(p.Hostname) {
		return fmt.Errorf("hostname must be a DNS hostname or IP address without a scheme, path, or port")
	}
	if p.ServerPort < 1 || p.ServerPort > 65535 {
		return fmt.Errorf("server_port must be between 1 and 65535")
	}
	if metricsPort < 1 || metricsPort > 65535 {
		return fmt.Errorf("metrics port must be between 1 and 65535")
	}
	listenIP := "::" // The same default as conf.NodeConfig.
	if opts != nil && opts.ListenIP != "" {
		listenIP = opts.ListenIP
	}
	addr, err := netip.ParseAddr(listenIP)
	if err != nil || addr.Zone() != "" {
		return fmt.Errorf("ListenIP must be a numeric IPv4 or IPv6 address without a zone or port")
	}

	switch p.CertType {
	case "self-signed":
	case "letsencrypt":
		// Reject display names and control characters: this field is an ACME
		// account address, rather than an email message's recipient header.
		email, err := mail.ParseAddress(p.AcmeEmail)
		if err != nil || email.Address != p.AcmeEmail || hasControl(p.AcmeEmail) {
			return fmt.Errorf("letsencrypt requires a valid acme_email address")
		}
	case "provided":
		if strings.TrimSpace(p.CertChainPath) == "" || hasControl(p.CertChainPath) {
			return fmt.Errorf("provided requires a cert_chain_path without control characters")
		}
		if strings.TrimSpace(p.CertKeyPath) == "" || hasControl(p.CertKeyPath) {
			return fmt.Errorf("provided requires a cert_key_path without control characters")
		}
		if err := verifyProvidedCertificate(dir, p); err != nil {
			return err
		}
	default:
		return fmt.Errorf("cert_type must explicitly be self-signed, letsencrypt, or provided")
	}
	certificates, err := t.newCertificateLifecycle(dir, p)
	if err != nil {
		return err
	}
	snapshot, err := certificates.prepare()
	if err != nil {
		return err
	}
	// Issuance and renewal belong to the shared V2bX certificate manager.
	// The native wizard receives only immutable, already validated files.
	certArgs := []string{"--cert-type", "provided", "--cert-chain-path", snapshot.certPath, "--cert-key-path", snapshot.keyPath}

	// The native wizard requires at least one client. Its temporary credential
	// must be unpredictable even if generation fails before start replaces it.
	credential, err := bootstrapCredential()
	if err != nil {
		return fmt.Errorf("create wizard credential: %w", err)
	}
	args := []string{
		"-m", "non-interactive",
		"-n", p.Hostname,
		"-a", net.JoinHostPort(addr.String(), strconv.Itoa(p.ServerPort)),
		"-c", credential,
		"--lib-settings", "./vpn.toml",
		"--hosts-settings", "./hosts.toml",
	}
	args = append(args, certArgs...)
	ctx, cancel := context.WithTimeout(context.Background(), wizardTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, t.binPath(wizardBin), args...)
	cmd.Dir = dir
	// The wizard can echo its arguments, including credentials and private
	// certificate material. Never include stdout or stderr in logs or errors.
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("wizard exceeded its %s timeout", wizardTimeout)
		}
		return fmt.Errorf("wizard failed: %w", err)
	}
	if err := setProvidedHostname(filepath.Join(dir, "hosts.toml"), p.Hostname); err != nil {
		return err
	}

	vpn := filepath.Join(dir, "vpn.toml")
	if err := enableMetrics(vpn, metricsPort); err != nil {
		return err
	}
	if p.HasIPv6 != nil {
		return setTopLevel(vpn, "ipv6_available", strconv.FormatBool(*p.HasIPv6))
	}
	return nil
}

func verifyProvidedCertificate(dir string, p *panel.TrustTunnelNode) error {
	resolve := func(path string) string {
		if filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(dir, path)
	}
	pair, err := tls.LoadX509KeyPair(resolve(p.CertChainPath), resolve(p.CertKeyPath))
	if err != nil {
		// PEM parser errors and filesystem errors can include private data or
		// paths. Give the operator the failing contract without echoing either.
		return fmt.Errorf("provided certificate and private key must be readable PEM files and form a matching pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("provided certificate is not a valid X.509 leaf")
	}
	if err := leaf.VerifyHostname(p.Hostname); err != nil {
		return fmt.Errorf("provided certificate does not cover the panel hostname")
	}
	return nil
}

// The native wizard derives provided-certificate hostnames from the entire
// certificate subject, rather than the requested hostname. A SAN-only leaf or
// a certificate with a different CN would select the wrong TLS host. Keep its
// generated paths and future settings, replacing only the one main hostname.
func setProvidedHostname(path, hostname string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read generated hosts.toml: %w", err)
	}
	var settings map[string]any
	if err := toml.Unmarshal(raw, &settings); err != nil {
		return fmt.Errorf("wizard generated invalid hosts.toml")
	}
	hosts, ok := settings["main_hosts"].([]any)
	if !ok || len(hosts) != 1 {
		return fmt.Errorf("wizard must generate exactly one main TLS host")
	}
	host, ok := hosts[0].(map[string]any)
	if !ok {
		return fmt.Errorf("wizard generated an invalid main TLS host")
	}
	host["hostname"] = hostname
	raw, err = toml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("encode generated hosts.toml")
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write generated hosts.toml: %w", err)
	}
	return nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

func validEndpointHostname(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	// A trailing root dot is valid in an otherwise ordinary DNS hostname.
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return true
}
