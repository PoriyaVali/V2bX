package certmanager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"

	"github.com/PoriyaVali/V2bX/common/file"
	"github.com/PoriyaVali/V2bX/common/tlscert"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
)

type Lego struct {
	client *lego.Client
	config *conf.CertConfig
	issuer CertificateIssuer
}

// CertificateIssuer is the certificate operation used for issuance and
// renewal. Per-instance injection permits isolated CA tests without mutating
// global factories or allowing tests to contact a public authority.
type CertificateIssuer interface {
	Obtain(certificate.ObtainRequest) (*certificate.Resource, error)
}

func NewLegoWithIssuer(config *conf.CertConfig, issuer CertificateIssuer) (*Lego, error) {
	l, err := NewLego(config)
	if err != nil {
		return nil, err
	}
	if issuer == nil {
		return nil, fmt.Errorf("certificate issuer is missing")
	}
	l.issuer = issuer
	return l, nil
}

// HTTP-01 owns port 80 and DNS providers consume process environment values.
// Serialize ACME operations so different nodes cannot mix DNS credentials,
// overwrite account files or compete for the challenge listener.
var acmeOperationMu sync.Mutex

func NewLego(config *conf.CertConfig) (*Lego, error) {
	if config == nil || (config.CertMode != "http" && config.CertMode != "dns") {
		return nil, fmt.Errorf("ACME requires http or dns certificate mode")
	}
	if config.CertDomain == "" || config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("ACME requires a domain and certificate/key paths")
	}
	domainInput := config.CertDomain
	wildcard := config.CertMode == "dns" && strings.HasPrefix(domainInput, "*.")
	if wildcard {
		domainInput = strings.TrimPrefix(domainInput, "*.")
	}
	domain, err := tlscert.Domain(domainInput)
	if err != nil {
		return nil, fmt.Errorf("ACME requires a valid DNS hostname")
	}
	if wildcard {
		domain = "*." + domain
	}
	if config.CertMode == "dns" && config.Provider == "" {
		return nil, fmt.Errorf("DNS certificate mode requires a provider")
	}
	if config.CertMode == "http" && config.HTTPWebRoot != "" {
		info, err := os.Stat(config.HTTPWebRoot)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("HTTPWebRoot must be an existing web server document root")
		}
	}
	for key := range config.DNSEnv {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return nil, fmt.Errorf("invalid DNS environment variable name")
		}
	}
	if config.Email != "" {
		address, err := mail.ParseAddress(config.Email)
		if err != nil || address.Address != config.Email || strings.ContainsAny(config.Email, `/\\`) {
			return nil, fmt.Errorf("invalid ACME account email")
		}
	}
	copy := *config
	copy.CertDomain = domain
	copy.DNSEnv = make(map[string]string, len(config.DNSEnv))
	for k, v := range config.DNSEnv {
		copy.DNSEnv[k] = v
	}
	copy.ExpandPaths()
	return &Lego{config: &copy}, nil
}

func (l *Lego) initClient() error {
	if l.issuer != nil {
		return nil
	}
	accountDir := l.config.AccountDir
	if accountDir == "" {
		accountDir = filepath.Join(filepath.Dir(l.config.CertFile), "user")
	}
	user, err := NewLegoUser(filepath.Join(accountDir, fmt.Sprintf("user-%s.json", l.config.Email)), l.config.Email)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	c := lego.NewConfig(user)
	c.Certificate.KeyType = certcrypto.RSA2048
	l.client, err = lego.NewClient(c)
	if err != nil {
		return err
	}
	if err := l.SetProvider(); err != nil {
		return err
	}
	l.issuer = l.client.Certificate
	return nil
}

func withACMEEnvironment(values map[string]string, operation func() error) error {
	acmeOperationMu.Lock()
	defer acmeOperationMu.Unlock()
	type previous struct {
		value   string
		present bool
	}
	old := make(map[string]previous, len(values))
	defer func() {
		for key, value := range old {
			if value.present {
				_ = os.Setenv(key, value.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}()
	for key, value := range values {
		v, present := os.LookupEnv(key)
		old[key] = previous{v, present}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("invalid DNS environment variable %q", key)
		}
	}
	return operation()
}

func checkPath(p string) error {
	if !file.IsExist(filepath.Dir(p)) {
		err := os.MkdirAll(filepath.Dir(p), 0755)
		if err != nil {
			return fmt.Errorf("create dir error: %s", err)
		}
	}
	return nil
}

func (l *Lego) SetProvider() error {
	switch l.config.CertMode {
	case "http":
		if l.config.HTTPWebRoot != "" {
			provider, err := webroot.NewHTTPProvider(l.config.HTTPWebRoot)
			if err != nil {
				return err
			}
			return l.client.Challenge.SetHTTP01Provider(provider)
		}
		err := l.client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
		if err != nil {
			return err
		}
	case "dns":
		p, err := dns.NewDNSChallengeProviderByName(l.config.Provider)
		if err != nil {
			return fmt.Errorf("create dns challenge provider error: %s", err)
		}
		err = l.client.Challenge.SetDNS01Provider(p)
		if err != nil {
			return fmt.Errorf("set dns provider error: %s", err)
		}
	}
	return nil
}

func (l *Lego) CreateCert() (err error) {
	return withACMEEnvironment(l.config.DNSEnv, func() error {
		// A different node sharing these paths may have issued while we
		// waited for the challenge/account lock.
		if validManagedCertificatePair(l.config) == nil {
			return nil
		}
		if err := l.initClient(); err != nil {
			return err
		}
		request := certificate.ObtainRequest{
			Domains: []string{l.config.CertDomain},
			Bundle:  true,
		}
		certificates, err := l.issuer.Obtain(request)
		if err != nil {
			return fmt.Errorf("obtain certificate error: %s", err)
		}
		err = l.writeCert(certificates)
		if err != nil {
			return fmt.Errorf("write certificate error: %s", err)
		}
		return nil
	})
}

func (l *Lego) RenewCert() error {
	// The common renewal check must be entirely local: no registration,
	// directory fetch or DNS-provider setup while a certificate is not due.
	if !l.renewalDue() {
		return nil
	}
	return withACMEEnvironment(l.config.DNSEnv, func() error {
		if !l.renewalDue() {
			return nil
		}
		if l.config.CertDomain == "" {
			return fmt.Errorf("renewal requires a configured certificate domain")
		}
		if err := l.initClient(); err != nil {
			return err
		}
		// Lego's Renew derives identifiers from every SAN in the old leaf,
		// ignoring Resource.Domain. A reused multi-name certificate can contain
		// obsolete domains the operator no longer controls. Renew the exact
		// configured identity instead, including when old files are damaged.
		res, err := l.issuer.Obtain(certificate.ObtainRequest{
			Domains: []string{l.config.CertDomain}, Bundle: true,
		})
		if err != nil {
			return err
		}
		err = l.writeCert(res)
		if err != nil {
			return fmt.Errorf("write certificate error: %s", err)
		}
		return nil
	})
}

func (l *Lego) renewalDue() bool {
	if validManagedCertificatePair(l.config) != nil {
		return true
	}
	data, err := os.ReadFile(l.config.CertFile)
	if err != nil {
		return true
	}
	due, err := l.CheckCert(data)
	return err != nil || due
}

func (l *Lego) CheckCert(file []byte) (bool, error) {
	cert, err := certcrypto.ParsePEMCertificate(file)
	if err != nil {
		return false, err
	}
	return certificateDueAt(cert, time.Now()), nil
}
func (l *Lego) parseParams(path string) string {
	r := strings.NewReplacer("{domain}", l.config.CertDomain,
		"{email}", l.config.Email)
	return r.Replace(path)
}
func (l *Lego) writeCert(certificates *certificate.Resource) error {
	if certificates == nil {
		return fmt.Errorf("ACME returned no certificate")
	}
	pair, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return fmt.Errorf("ACME returned an invalid certificate pair: %w", err)
	}
	if _, err := validateCertificatePair(pair, l.config.CertDomain); err != nil {
		return fmt.Errorf("invalid certificate replacement: %w", err)
	}
	err = checkPath(l.config.CertFile)
	if err != nil {
		return fmt.Errorf("check path error: %s", err)
	}
	err = checkPath(l.config.KeyFile)
	if err != nil {
		return fmt.Errorf("check path error: %s", err)
	}
	// 0600: the certificate's private key. It was written readable by every
	// account on the machine. WriteFile keeps the mode of a file that already
	// exists, so a key written before this is tightened too.
	keyPath := l.parseParams(l.config.KeyFile)
	certPath := l.parseParams(l.config.CertFile)
	keyAbs, err := filepath.Abs(keyPath)
	if err != nil {
		return err
	}
	certAbs, err := filepath.Abs(certPath)
	if err != nil {
		return err
	}
	if keyAbs == certAbs || (runtime.GOOS == "windows" && strings.EqualFold(keyAbs, certAbs)) {
		combined := append(append(append([]byte(nil), certificates.Certificate...), '\n'), certificates.PrivateKey...)
		return file.WriteAtomic(certPath, combined, 0600)
	}
	oldKey, oldErr := os.ReadFile(keyPath)
	if oldErr != nil && !os.IsNotExist(oldErr) {
		return oldErr
	}
	if err = file.WriteAtomic(keyPath, certificates.PrivateKey, 0600); err != nil {
		return err
	}
	if err = file.WriteAtomic(certPath, certificates.Certificate, 0644); err != nil {
		if oldErr == nil {
			return errors.Join(err, file.WriteAtomic(keyPath, oldKey, 0600))
		}
		return errors.Join(err, os.Remove(keyPath))
	}
	return nil
}

type User struct {
	Email        string                 `json:"Email"`
	Registration *registration.Resource `json:"Registration"`
	key          crypto.PrivateKey
	KeyEncoded   string `json:"Key"`
}

func (u *User) GetEmail() string {
	return u.Email
}
func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func NewLegoUser(path string, email string) (*User, error) {
	var user User
	if file.IsExist(path) {
		err := user.Load(path)
		if err != nil {
			return nil, err
		}
		if user.Email != email {
			user.Registration = nil
			user.Email = email
			err := registerUser(&user, path)
			if err != nil {
				return nil, err
			}
		}
	} else {
		user.Email = email
		err := registerUser(&user, path)
		if err != nil {
			return nil, err
		}
	}
	return &user, nil
}

func registerUser(user *User, path string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key error: %s", err)
	}
	user.key = privateKey
	c := lego.NewConfig(user)
	client, err := lego.NewClient(c)
	if err != nil {
		return fmt.Errorf("create lego client error: %s", err)
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	user.Registration = reg
	err = user.Save(path)
	if err != nil {
		return fmt.Errorf("save user error: %s", err)
	}
	return nil
}

func EncodePrivate(privKey *ecdsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	return string(pemEncoded), nil
}
func (u *User) Save(path string) error {
	err := checkPath(path)
	if err != nil {
		return fmt.Errorf("check path error: %s", err)
	}
	u.KeyEncoded, _ = EncodePrivate(u.key.(*ecdsa.PrivateKey))
	defer func() { u.KeyEncoded = "" }()
	// 0600, and closed: the file holds the ACME account's private key. It was
	// world-readable and the descriptor was never closed.
	data, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("marshal account: %w", err)
	}
	return file.WriteAtomic(path, data, 0600)
}

func (u *User) DecodePrivate(pemEncodedPriv string) (*ecdsa.PrivateKey, error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))
	if blockPriv == nil {
		return nil, fmt.Errorf("no PEM block in the saved account key")
	}
	x509EncodedPriv := blockPriv.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509EncodedPriv)
	return privateKey, err
}

func (u *User) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("open file error: %s", err)
	}

	err = json.Unmarshal(data, u)
	if err != nil {
		return fmt.Errorf("unmarshal json error: %s", err)
	}
	u.key, err = u.DecodePrivate(u.KeyEncoded)
	if err != nil {
		return fmt.Errorf("decode private key error: %s", err)
	}
	return nil
}
