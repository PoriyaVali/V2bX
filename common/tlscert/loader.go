package tlscert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Loader shares immutable parsed certificates between handshakes. File checks
// are bounded by interval; a partially installed or invalid replacement keeps
// the last valid pair available until a complete replacement can be loaded.
type Loader struct {
	certPath, keyPath string
	domain            string
	interval          time.Duration
	current           atomic.Pointer[tls.Certificate]
	nextCheck         atomic.Int64
	mu                sync.Mutex
	certInfo, keyInfo os.FileInfo
}

func New(certPath, keyPath string, interval time.Duration) (*Loader, error) {
	return NewForDomain(certPath, keyPath, "", interval)
}

// NewForDomain also prevents a valid but unrelated replacement from taking
// over a listener whose configured certificate identity has not changed.
func NewForDomain(certPath, keyPath, domain string, interval time.Duration) (*Loader, error) {
	l := &Loader{certPath: certPath, keyPath: keyPath, domain: domain, interval: interval}
	if err := l.refresh(); err != nil {
		return nil, err
	}
	l.nextCheck.Store(time.Now().Add(interval).UnixNano())
	return l, nil
}

func (l *Loader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if time.Now().UnixNano() >= l.nextCheck.Load() {
		l.mu.Lock()
		if time.Now().UnixNano() >= l.nextCheck.Load() {
			// Retry a bad replacement on the next interval, without parsing
			// it on every new connection or exposing the broken pair.
			_ = l.refresh()
			l.nextCheck.Store(time.Now().Add(l.interval).UnixNano())
		}
		l.mu.Unlock()
	}
	return l.current.Load(), nil
}

func sameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime() == b.ModTime()
}

func (l *Loader) refresh() error {
	certInfo, err := os.Stat(l.certPath)
	if err != nil {
		return err
	}
	keyInfo, err := os.Stat(l.keyPath)
	if err != nil {
		return err
	}
	if sameFile(l.certInfo, certInfo) && sameFile(l.keyInfo, keyInfo) {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return fmt.Errorf("load TLS certificate pair: %w", err)
	}
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
	}
	if time.Now().Before(cert.Leaf.NotBefore) || !time.Now().Before(cert.Leaf.NotAfter) {
		return fmt.Errorf("replacement TLS certificate is not currently valid")
	}
	if len(cert.Leaf.ExtKeyUsage) > 0 || len(cert.Leaf.UnknownExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range cert.Leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
			}
		}
		if !serverAuth {
			return fmt.Errorf("replacement TLS certificate does not permit server authentication")
		}
	}
	if l.domain != "" {
		if err := cert.Leaf.VerifyHostname(l.domain); err != nil {
			return fmt.Errorf("replacement TLS certificate hostname mismatch: %w", err)
		}
	}
	l.certInfo, l.keyInfo = certInfo, keyInfo
	l.current.Store(&cert)
	return nil
}
