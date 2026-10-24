package trusttunnel

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/certmanager"
	"github.com/PoriyaVali/V2bX/common/file"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/pelletier/go-toml/v2"
	log "github.com/sirupsen/logrus"
)

const (
	certificatePollInterval  = 5 * time.Second
	certificateRenewInterval = 6 * time.Hour
	certificateRetryInterval = time.Hour
)

type certificateOperations interface {
	Ensure(*conf.CertConfig) error
	Renew(*conf.CertConfig) error
}

type managedCertificateOperations struct{}

func (managedCertificateOperations) Ensure(c *conf.CertConfig) error { return certmanager.Ensure(c) }
func (managedCertificateOperations) Renew(c *conf.CertConfig) error  { return certmanager.Renew(c) }

type certificateLifecycle struct {
	dir            string
	hostname       string
	config         *conf.CertConfig
	ops            certificateOperations
	nextRenew      time.Time
	pendingPublish bool
}

type certificateSnapshot struct {
	certPath string
	keyPath  string
}

func (t *TrustTunnel) newCertificateLifecycle(dir string, p *panel.TrustTunnelNode) (*certificateLifecycle, error) {
	if p == nil || !validEndpointHostname(p.Hostname) {
		return nil, fmt.Errorf("TrustTunnel certificate requires a valid panel hostname")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint certificate directory")
	}
	ops := t.certificateOps
	if ops == nil {
		ops = managedCertificateOperations{}
	}
	config := &conf.CertConfig{CertDomain: p.Hostname, Email: p.AcmeEmail}
	switch p.CertType {
	case "provided":
		config.CertMode = "file"
		config.CertFile, config.KeyFile = p.CertChainPath, p.CertKeyPath
		if config.CertFile == "" || config.KeyFile == "" {
			return nil, fmt.Errorf("provided certificate requires certificate and key paths")
		}
		if !filepath.IsAbs(config.CertFile) {
			config.CertFile = filepath.Join(dir, config.CertFile)
		}
		if !filepath.IsAbs(config.KeyFile) {
			config.KeyFile = filepath.Join(dir, config.KeyFile)
		}
	case "self-signed", "letsencrypt":
		config.CertMode = "self"
		if p.CertType == "letsencrypt" {
			config.CertMode = "http"
		}
		identity, _ := json.Marshal([]string{p.CertType, p.Hostname, p.AcmeEmail})
		source := filepath.Join(dir, "certificate-source", fmt.Sprintf("%x", sha256.Sum256(identity)))
		config.CertFile = filepath.Join(source, "cert.pem")
		config.KeyFile = filepath.Join(source, "key.pem")
		config.AccountDir = filepath.Join(source, "account")
	default:
		return nil, fmt.Errorf("unsupported TrustTunnel certificate mode")
	}
	return &certificateLifecycle{dir: dir, hostname: p.Hostname, config: config, ops: ops}, nil
}

// Only validated immutable files are exposed to the native process. A reload
// caused by a user sync can therefore never catch an external cert/key update
// between its two writes.
func (c *certificateLifecycle) prepare() (*certificateSnapshot, error) {
	if err := c.ops.Ensure(c.config); err != nil {
		return nil, fmt.Errorf("could not prepare the TrustTunnel certificate: %w", err)
	}
	return c.snapshot(time.Now())
}

func (c *certificateLifecycle) snapshot(now time.Time) (*certificateSnapshot, error) {
	certPEM, err := os.ReadFile(c.config.CertFile)
	if err != nil {
		return nil, fmt.Errorf("endpoint certificate is unreadable")
	}
	keyPEM, err := os.ReadFile(c.config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("endpoint certificate private key is unreadable")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("endpoint certificate and key must be a matching PEM pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("endpoint leaf certificate is invalid")
	}
	if leaf.VerifyHostname(c.hostname) != nil {
		return nil, fmt.Errorf("endpoint certificate does not cover the panel hostname")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("endpoint certificate is outside its validity period")
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
			}
		}
		if !serverAuth {
			return nil, fmt.Errorf("endpoint certificate does not permit server authentication")
		}
	}
	hash := sha256.New()
	hash.Write(certPEM)
	hash.Write([]byte{0})
	hash.Write(keyPEM)
	version := filepath.Join(c.dir, "certificates", fmt.Sprintf("%x", hash.Sum(nil)))
	certPath, keyPath := filepath.Join(version, "cert.pem"), filepath.Join(version, "key.pem")
	if _, err := os.Stat(certPath); err == nil {
		existingCert, certErr := os.ReadFile(certPath)
		existingKey, keyErr := os.ReadFile(keyPath)
		if certErr == nil && keyErr == nil && bytes.Equal(existingCert, certPEM) && bytes.Equal(existingKey, keyPEM) {
			return &certificateSnapshot{certPath, keyPath}, nil
		}
		return nil, fmt.Errorf("immutable endpoint certificate snapshot was damaged")
	}
	if err := os.MkdirAll(filepath.Dir(version), 0o700); err != nil {
		return nil, fmt.Errorf("create endpoint certificate directory")
	}
	stage, err := os.MkdirTemp(filepath.Dir(version), ".pending-")
	if err != nil {
		return nil, fmt.Errorf("stage endpoint certificate")
	}
	defer os.RemoveAll(stage)
	if err := os.WriteFile(filepath.Join(stage, "cert.pem"), certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("stage endpoint certificate")
	}
	if err := os.WriteFile(filepath.Join(stage, "key.pem"), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("stage endpoint private key")
	}
	if err := os.Rename(stage, version); err != nil {
		// An old lifecycle finishing renewal can create the same immutable
		// version while its replacement is preparing startup.
		existingCert, certErr := os.ReadFile(certPath)
		existingKey, keyErr := os.ReadFile(keyPath)
		if certErr != nil || keyErr != nil || !bytes.Equal(existingCert, certPEM) || !bytes.Equal(existingKey, keyPEM) {
			return nil, fmt.Errorf("install immutable endpoint certificate")
		}
	}
	return &certificateSnapshot{certPath, keyPath}, nil
}

func (c *certificateLifecycle) run(stop <-chan struct{}, publish func(func() error) error) {
	ticker := time.NewTicker(certificatePollInterval)
	defer ticker.Stop()
	lastError := ""
	for {
		select {
		case <-stop:
			return
		default:
		}
		if err := c.refresh(time.Now(), publish); err != nil {
			if err.Error() != lastError {
				log.WithField("hostname", c.hostname).Error("trusttunnel: certificate maintenance failed; retaining the active TLS pair: ", err)
			}
			lastError = err.Error()
		} else {
			lastError = ""
		}
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func (c *certificateLifecycle) refresh(now time.Time, publish func(func() error) error) error {
	if c.config.CertMode != "file" && !now.Before(c.nextRenew) {
		if err := c.ops.Renew(c.config); err != nil {
			c.nextRenew = now.Add(certificateRetryInterval)
			return fmt.Errorf("managed endpoint certificate renewal failed: %w", err)
		}
		c.nextRenew = now.Add(certificateRenewInterval)
	}
	snapshot, err := c.snapshot(now)
	if err != nil {
		return err
	}
	path := filepath.Join(c.dir, "hosts.toml")
	settings, host, err := certificateHostSettings(path)
	if err != nil {
		return err
	}
	if host["cert_chain_path"] == snapshot.certPath && host["private_key_path"] == snapshot.keyPath && host["hostname"] == c.hostname && !c.pendingPublish {
		return nil
	}
	host["cert_chain_path"], host["private_key_path"], host["hostname"] = snapshot.certPath, snapshot.keyPath, c.hostname
	raw, err := toml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("encode renewed endpoint TLS settings")
	}
	err = publish(func() error { return file.WriteAtomic(path, raw, 0o600) })
	c.pendingPublish = err != nil
	return err
}

func certificateHostSettings(path string) (map[string]any, map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read endpoint TLS settings")
	}
	var settings map[string]any
	if err := toml.Unmarshal(raw, &settings); err != nil {
		return nil, nil, fmt.Errorf("endpoint TLS settings must be valid TOML")
	}
	hosts, ok := settings["main_hosts"].([]any)
	if !ok || len(hosts) != 1 {
		return nil, nil, fmt.Errorf("endpoint TLS settings require exactly one main host")
	}
	host, ok := hosts[0].(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("invalid endpoint TLS host")
	}
	return settings, host, nil
}
