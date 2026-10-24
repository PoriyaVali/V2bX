package trusttunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/pelletier/go-toml/v2"
)

// TestMain routes the child process here before testing parses the wizard's
// native arguments. This exercises exec.Command, arguments, and working dir.
func runConfigWizardHelper() bool {
	mode := os.Getenv("TT_FAKE_WIZARD")
	if mode == "" {
		return false
	}
	args, _ := json.Marshal(os.Args[1:])
	if err := os.WriteFile("wizard-args.json", args, 0o600); err != nil {
		os.Exit(91)
	}
	if mode == "fail" {
		fmt.Fprintln(os.Stderr, "wizard echoed sensitive arguments:", strings.Join(os.Args[1:], " "))
		os.Exit(23)
	}
	if err := os.WriteFile("vpn.toml", []byte(wizardVpnToml+`
# [metrics]
# address = "127.0.0.1:0"
# request_timeout_secs = 3
`), 0o600); err != nil {
		os.Exit(92)
	}
	hostname := argumentValue(os.Args[1:], "-n")
	if argumentValue(os.Args[1:], "--cert-type") == "provided" {
		hostname = "CN=legacy.example.test, O=Example"
	}
	hosts := fmt.Sprintf(`[[main_hosts]]
hostname = %q
cert_chain_path = %q
private_key_path = %q
allowed_sni = ["alias.example.test"]
future_setting = "retain main setting"

[extensions]
future_setting = "retain extra table"

[[ping_hosts]]
hostname = "ping.example.test"
cert_chain_path = "ping-cert.pem"
private_key_path = "ping-key.pem"
`, hostname, argumentValue(os.Args[1:], "--cert-chain-path"), argumentValue(os.Args[1:], "--cert-key-path"))
	if err := os.WriteFile("hosts.toml", []byte(hosts), 0o600); err != nil {
		os.Exit(93)
	}
	// Match the native wizard's requirement that a client exists in this file.
	credential := argumentValue(os.Args[1:], "-c")
	name, pass, _ := strings.Cut(credential, ":")
	clients := fmt.Sprintf("[[client]]\nusername = %q\npassword = %q\n", name, pass)
	if err := os.WriteFile("credentials.toml", []byte(clients), 0o600); err != nil {
		os.Exit(94)
	}
	os.Exit(0)
	return true
}

func argumentValue(args []string, key string) string {
	for i, arg := range args {
		if arg == key && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func configWizardFixture(t *testing.T) *TrustTunnel {
	t.Helper()
	t.Setenv("TT_FAKE_WIZARD", "ok")
	binDir := t.TempDir()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(binDir, wizardBin)
	if runtime.GOOS == "windows" {
		target += ".exe"
	}
	if err := os.Link(bin, target); err != nil {
		in, err := os.Open(bin)
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatalf("copy wizard helper: %v, close: %v", copyErr, closeErr)
		}
	}
	return &TrustTunnel{binDir: binDir, certificateOps: isolatedCertificateOperations(t)}
}

func validConfigParams() *panel.TrustTunnelNode {
	return &panel.TrustTunnelNode{
		CommonNode: panel.CommonNode{ServerPort: 8443, Host: "subscription.example.test", ServerName: "sni.example.test"},
		Hostname:   "endpoint.example.test",
		CertType:   "self-signed",
	}
}

func providedCertificateFixture(t *testing.T, hostname, commonName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName},
		DNSNames: []string{hostname}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "provided cert files")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	chainPath, keyPath := filepath.Join(dir, "private-chain-marker.pem"), filepath.Join(dir, "private-key-marker.pem")
	for _, file := range []struct {
		path, kind string
		data       []byte
	}{
		{chainPath, "CERTIFICATE", der}, {keyPath, "PRIVATE KEY", keyDER},
	} {
		if err := os.WriteFile(file.path, pem.EncodeToMemory(&pem.Block{Type: file.kind, Bytes: file.data}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return chainPath, keyPath
}

func readWizardArgs(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "wizard-args.json"))
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	return args
}

func TestGenerateConfig_ListenAddressAndHostname(t *testing.T) {
	tt := configWizardFixture(t)
	for _, tc := range []struct {
		name string
		opts *conf.Options
		want string
	}{
		{"nil defaults to IPv6 wildcard", nil, "[::]:8443"},
		{"empty defaults to IPv6 wildcard", &conf.Options{}, "[::]:8443"},
		{"IPv4 loopback", &conf.Options{ListenIP: "127.0.0.1"}, "127.0.0.1:8443"},
		{"IPv4 wildcard", &conf.Options{ListenIP: "0.0.0.0"}, "0.0.0.0:8443"},
		{"IPv6 loopback", &conf.Options{ListenIP: "::1"}, "[::1]:8443"},
		{"IPv6 interface", &conf.Options{ListenIP: "2001:db8::42"}, "[2001:db8::42]:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := tt.generateConfig(dir, validConfigParams(), 9191, tc.opts); err != nil {
				t.Fatal(err)
			}
			args := readWizardArgs(t, dir)
			if got := argumentValue(args, "-a"); got != tc.want {
				t.Fatalf("listen address = %q, want %q", got, tc.want)
			}
			if got := argumentValue(args, "-n"); got != "endpoint.example.test" {
				t.Fatalf("certificate hostname = %q; must use panel hostname", got)
			}
		})
	}
}

func TestGenerateConfig_ExplicitCertificateModes(t *testing.T) {
	tt := configWizardFixture(t)
	for _, mode := range []string{"self-signed", "letsencrypt", "provided"} {
		t.Run(mode, func(t *testing.T) {
			p := validConfigParams()
			p.CertType, p.AcmeEmail = mode, "admin@example.test"
			p.CertChainPath, p.CertKeyPath = "/custom chain/cert.pem", "/custom key/key.pem"
			if mode == "provided" {
				p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "")
			}
			opts := &conf.Options{ListenIP: "127.0.0.1", CertConfig: &conf.CertConfig{
				CertMode: "dns", CertDomain: "generic.example.test", Email: "generic@example.test",
				CertFile: "/generic/cert.pem", KeyFile: "/generic/key.pem",
			}}
			dir := t.TempDir()
			if err := tt.generateConfig(dir, p, 9191, opts); err != nil {
				t.Fatal(err)
			}
			args := readWizardArgs(t, dir)
			if got := argumentValue(args, "--cert-type"); got != "provided" {
				t.Fatalf("native certificate mode = %q, want pre-managed provided pair", got)
			}
			if got := argumentValue(args, "-n"); got != p.Hostname {
				t.Fatal("generic CertConfig replaced the panel hostname")
			}
			if got := argumentValue(args, "--acme-email"); got != "" {
				t.Fatal("native wizard was asked to own ACME instead of the shared manager")
			}
			for _, field := range []struct{ flag, want string }{
				{"--cert-chain-path", p.CertChainPath}, {"--cert-key-path", p.CertKeyPath},
			} {
				got := argumentValue(args, field.flag)
				if got == "" || got == field.want || !filepath.IsAbs(got) {
					t.Fatalf("%s does not point to an isolated immutable snapshot for %s", field.flag, mode)
				}
				if _, err := os.Stat(got); err != nil {
					t.Fatalf("snapshot passed to native wizard does not exist: %v", err)
				}
			}
		})
	}
}

func TestGenerateConfig_RejectsInvalidInputBeforeWizard(t *testing.T) {
	tt := configWizardFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*panel.TrustTunnelNode, *conf.Options)
	}{
		{"missing certificate mode", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.CertType = "" }},
		{"unknown certificate mode", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.CertType = "self_signed" }},
		{"certificate mode whitespace", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.CertType = "self-signed " }},
		{"certificate mode NUL", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.CertType = "self-signed\x00" }},
		{"missing hostname", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.Hostname = "" }},
		{"URL hostname", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.Hostname = "https://example.test" }},
		{"port in hostname", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.Hostname = "example.test:443" }},
		{"hostname NUL", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.Hostname = "example.test\x00" }},
		{"hostname whitespace", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.Hostname = " example.test" }},
		{"hostname flag", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.Hostname = "--cert-type" }},
		{"zero port", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.ServerPort = 0 }},
		{"negative port", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.ServerPort = -1 }},
		{"large port", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.ServerPort = 65536 }},
		{"listen DNS", func(_ *panel.TrustTunnelNode, o *conf.Options) { o.ListenIP = "localhost" }},
		{"listen port", func(_ *panel.TrustTunnelNode, o *conf.Options) { o.ListenIP = "127.0.0.1:8443" }},
		{"listen brackets", func(_ *panel.TrustTunnelNode, o *conf.Options) { o.ListenIP = "[::1]" }},
		{"listen zone", func(_ *panel.TrustTunnelNode, o *conf.Options) { o.ListenIP = "fe80::1%eth0" }},
		{"listen NUL", func(_ *panel.TrustTunnelNode, o *conf.Options) { o.ListenIP = "127.0.0.1\x00" }},
		{"missing ACME email", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.CertType = "letsencrypt" }},
		{"invalid ACME email", func(p *panel.TrustTunnelNode, _ *conf.Options) { p.CertType, p.AcmeEmail = "letsencrypt", "invalid" }},
		{"ACME display name", func(p *panel.TrustTunnelNode, _ *conf.Options) {
			p.CertType, p.AcmeEmail = "letsencrypt", "Admin <a@example.test>"
		}},
		{"ACME email NUL", func(p *panel.TrustTunnelNode, _ *conf.Options) {
			p.CertType, p.AcmeEmail = "letsencrypt", "a@example.test\x00"
		}},
		{"missing certificate chain", func(p *panel.TrustTunnelNode, _ *conf.Options) {
			p.CertType, p.CertKeyPath = "provided", "/cert/key.pem"
		}},
		{"missing certificate key", func(p *panel.TrustTunnelNode, _ *conf.Options) {
			p.CertType, p.CertChainPath = "provided", "/cert/chain.pem"
		}},
		{"certificate chain newline", func(p *panel.TrustTunnelNode, _ *conf.Options) {
			p.CertType, p.CertChainPath, p.CertKeyPath = "provided", "/cert/chain\n.pem", "/cert/key.pem"
		}},
		{"certificate key NUL", func(p *panel.TrustTunnelNode, _ *conf.Options) {
			p.CertType, p.CertChainPath, p.CertKeyPath = "provided", "/cert/chain.pem", "/cert/key\x00.pem"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, opts := validConfigParams(), &conf.Options{}
			tc.change(p, opts)
			dir := t.TempDir()
			if err := tt.generateConfig(dir, p, 9191, opts); err == nil {
				t.Fatal("invalid input accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "wizard-args.json")); !os.IsNotExist(err) {
				t.Fatal("wizard ran despite invalid input")
			}
		})
	}
}

func TestGenerateConfig_MetricsAndIPv6(t *testing.T) {
	tt := configWizardFixture(t)
	for _, value := range []*bool{nil, new(true), new(false)} {
		p := validConfigParams()
		p.HasIPv6 = value
		dir := t.TempDir()
		if err := tt.generateConfig(dir, p, 9274, nil); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "vpn.toml"))
		if err != nil {
			t.Fatal(err)
		}
		want := "ipv6_available = true"
		if value != nil && !*value {
			want = "ipv6_available = false"
		}
		if !strings.Contains(string(raw), "\n"+want+"\n") || !strings.Contains(string(raw), "\n[metrics]\naddress = \"127.0.0.1:9274\"\nrequest_timeout_secs = 3") {
			t.Fatalf("native template settings were not preserved:\n%s", raw)
		}
		if !strings.Contains(string(raw), `ipv6_available = "a nested key`) {
			t.Fatal("nested key changed while setting top-level IPv6 availability")
		}
	}
}

func TestGenerateConfig_RandomCredentialAndSecretSafeFailure(t *testing.T) {
	tt := configWizardFixture(t)
	t.Setenv("TT_FAKE_WIZARD", "fail")
	p := validConfigParams()
	p.CertType = "provided"
	p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "")
	var previous string
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		err := tt.generateConfig(dir, p, 9191, nil)
		if err == nil || !strings.Contains(err.Error(), "wizard failed") || !strings.Contains(err.Error(), "23") {
			t.Fatalf("unexpected wizard failure: %v", err)
		}
		credential := argumentValue(readWizardArgs(t, dir), "-c")
		name, pass, found := strings.Cut(credential, ":")
		if !found || name == "" || len(pass) < 64 || credential == previous || strings.Contains(credential, "placeholder") {
			t.Fatal("wizard credential is fixed or has insufficient random material")
		}
		for _, secret := range []string{credential, name, pass, p.CertChainPath, p.CertKeyPath} {
			if strings.Contains(err.Error(), secret) {
				t.Fatal("wizard failure disclosed a sensitive argument")
			}
		}
		previous = credential
	}
}

func TestAddNode_PassesListenIPToWizard(t *testing.T) {
	tt := configWizardFixture(t)
	tt.workDir = t.TempDir()
	p := validConfigParams()
	// The endpoint is intentionally absent: inspect the wizard invocation
	// through the public AddNode path without running a supervised process.
	err := tt.AddNode("listen-test", &panel.NodeInfo{TrustTunnel: p}, &conf.Options{ListenIP: "::1"})
	if err == nil || !strings.Contains(err.Error(), "start listen-test") {
		t.Fatalf("expected unavailable endpoint after successful configuration: %v", err)
	}
	args := readWizardArgs(t, filepath.Join(tt.workDir, "listen-test"))
	if got := argumentValue(args, "-a"); got != "[::1]:8443" {
		t.Fatalf("AddNode passed listen address %q, want [::1]:8443", got)
	}
}

func TestGenerateConfig_ProvidedSANSelectsPanelHostname(t *testing.T) {
	tt := configWizardFixture(t)
	for _, commonName := range []string{"", "legacy.example.test"} {
		t.Run("CN="+commonName, func(t *testing.T) {
			p := validConfigParams()
			p.CertType = "provided"
			p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, commonName)
			// Native relative certificate paths are resolved in the node's
			// working directory. Verify preflight uses the same interpretation.
			dir := filepath.Dir(p.CertChainPath)
			p.CertChainPath, p.CertKeyPath = filepath.Base(p.CertChainPath), filepath.Base(p.CertKeyPath)
			if err := tt.generateConfig(dir, p, 9191, nil); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "hosts.toml"))
			if err != nil {
				t.Fatal(err)
			}
			var settings struct {
				MainHosts []struct {
					Hostname      string   `toml:"hostname"`
					CertChainPath string   `toml:"cert_chain_path"`
					KeyPath       string   `toml:"private_key_path"`
					AllowedSNI    []string `toml:"allowed_sni"`
					FutureSetting string   `toml:"future_setting"`
				} `toml:"main_hosts"`
				Extensions map[string]string `toml:"extensions"`
				PingHosts  []struct {
					Hostname string `toml:"hostname"`
				} `toml:"ping_hosts"`
			}
			if err := toml.Unmarshal(raw, &settings); err != nil {
				t.Fatal(err)
			}
			if len(settings.MainHosts) != 1 {
				t.Fatal("main host disappeared during normalization")
			}
			host := settings.MainHosts[0]
			if host.Hostname != p.Hostname || !filepath.IsAbs(host.CertChainPath) || !filepath.IsAbs(host.KeyPath) || host.CertChainPath == p.CertChainPath || host.KeyPath == p.CertKeyPath {
				t.Fatalf("generated host does not select the panel hostname and immutable pair: %+v", host)
			}
			for _, pair := range [][2]string{{host.CertChainPath, filepath.Join(dir, p.CertChainPath)}, {host.KeyPath, filepath.Join(dir, p.CertKeyPath)}} {
				copied, copyErr := os.ReadFile(pair[0])
				source, sourceErr := os.ReadFile(pair[1])
				if copyErr != nil || sourceErr != nil || string(copied) != string(source) {
					t.Fatal("immutable snapshot changed the provided certificate or key")
				}
			}
			if len(host.AllowedSNI) != 1 || host.AllowedSNI[0] != "alias.example.test" || host.FutureSetting != "retain main setting" || settings.Extensions["future_setting"] != "retain extra table" || len(settings.PingHosts) != 1 || settings.PingHosts[0].Hostname != "ping.example.test" {
				t.Fatal("normalizing the main hostname lost other native settings")
			}
		})
	}
}

func TestGenerateConfig_ProvidedRejectsWrongCertificateBeforeWizard(t *testing.T) {
	tt := configWizardFixture(t)
	for _, problem := range []string{"wrong hostname", "mismatched key", "missing file", "invalid PEM"} {
		t.Run(problem, func(t *testing.T) {
			p := validConfigParams()
			p.CertType = "provided"
			p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "")
			switch problem {
			case "wrong hostname":
				p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, "other.example.test", p.Hostname)
			case "mismatched key":
				_, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "")
			case "missing file":
				p.CertChainPath += ".missing"
			case "invalid PEM":
				if err := os.WriteFile(p.CertChainPath, []byte("private-invalid-pem-marker"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			err := tt.generateConfig(dir, p, 9191, nil)
			if err == nil || !strings.Contains(err.Error(), "provided certificate") {
				t.Fatalf("unexpected certificate validation result: %v", err)
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("certificate validation exposed a private path or PEM contents")
			}
			if _, err := os.Stat(filepath.Join(dir, "wizard-args.json")); !os.IsNotExist(err) {
				t.Fatal("wizard ran despite an unusable provided certificate")
			}
		})
	}
}

func TestSetProvidedHostname_RejectsUnexpectedNativeShape(t *testing.T) {
	for _, raw := range []string{
		"secret-value = [invalid-private-marker",
		"[[ping_hosts]]\nhostname = 'example.test'\n",
		"[[main_hosts]]\nhostname = 'one.test'\n[[main_hosts]]\nhostname = 'two.test'\n",
	} {
		path := filepath.Join(t.TempDir(), "hosts.toml")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := setProvidedHostname(path, "endpoint.example.test"); err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatalf("unexpected unsafe-hosts validation result: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != raw {
			t.Fatal("invalid native configuration was overwritten")
		}
	}
}
