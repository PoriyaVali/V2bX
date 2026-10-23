package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
)

func certificatePanel(t *testing.T, protocol, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/config" {
			t.Errorf("wizard called %s", r.URL.Path)
		}
		typ := r.URL.Query().Get("node_type")
		if typ == protocol || protocol == "hysteria2" && typ == "hysteria" {
			fmt.Fprint(w, body)
		} else {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("V2BX_TEST_API_KEY", "fictional-key")
	return server
}

func readSetupCert(t *testing.T, output string) *conf.CertConfig {
	t.Helper()
	parsed := conf.New()
	if err := parsed.LoadFromPath(output); err != nil {
		t.Fatal(err)
	}
	return parsed.NodeConfig[0].Options.CertConfig
}

func TestCertificateIssuanceUsesHostAcrossTLSProtocols(t *testing.T) {
	for _, row := range []struct{ protocol, fields string }{
		{"anytls", `"tls":1,"tls_settings":{"server_name":"nested-sni.example.test"}`},
		{"vless", `"tls":1,"network":"tcp","tls_settings":{"server_name":"nested-sni.example.test"}`},
		{"vmess", `"tls":1,"network":"tcp","tlsSettings":{"serverName":"legacy-sni.example.test"}`},
		{"trojan", `"network":"tcp"`}, {"tuic", `"congestion_control":"bbr"`},
		{"hysteria", `"version":1`}, {"hysteria2", `"version":2`},
	} {
		t.Run(row.protocol, func(t *testing.T) {
			srv := certificatePanel(t, row.protocol, `{"host":" OWNED.Example.Test. ","server_name":"top-sni.example.test","server_port":443,`+row.fields+`}`)
			for _, guided := range []bool{false, true} {
				output := filepath.Join(t.TempDir(), "config.json")
				var text string
				var err error
				if guided {
					text, err = executeGuidedTest(srv.URL, output, "none\n\n\nn\n1\n1\n\nn\n")
				} else {
					c := newConfigureCommand()
					c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", row.protocol + ":1", "--output", output})
					var buf bytes.Buffer
					c.SetOut(&buf)
					c.SetErr(&buf)
					err = c.Execute()
					text = buf.String()
				}
				if err != nil {
					t.Fatalf("guided=%v: %v\n%s", guided, err, text)
				}
				cert := readSetupCert(t, output)
				if cert.CertDomain != "owned.example.test" || cert.CertMode != "http" || strings.Contains(cert.CertFile, "sni") {
					t.Fatalf("SNI selected for ACME: %+v", cert)
				}
				if !strings.Contains(text, "verification name") {
					t.Fatal("SNI/certificate mismatch hidden from operator")
				}
			}
		})
	}
}

func TestCertificateMissingOrInvalidHostNeverFallsBackToSNI(t *testing.T) {
	for _, host := range []string{"", "192.0.2.10", "2001:db8::1", "https://node.example.test/path", "node.example.test:443", "../../node.example.test", "*.example.test"} {
		t.Run(host, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"host": host, "server_name": "third-party.example.test", "tls_settings": map[string]string{"server_name": "nested-third-party.example.test"}, "tls": 1, "server_port": 443})
			srv := certificatePanel(t, "anytls", string(body))
			output := filepath.Join(t.TempDir(), "config.json")
			original := []byte("operator configuration")
			if err := os.WriteFile(output, original, 0600); err != nil {
				t.Fatal(err)
			}
			c := newConfigureCommand()
			c.SetArgs([]string{"--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--nodes", "anytls:1", "--output", output})
			var buf bytes.Buffer
			c.SetOut(&buf)
			c.SetErr(&buf)
			if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "--cert-domain") {
				t.Fatalf("headless setup guessed SNI: %v", err)
			}
			actual, _ := os.ReadFile(output)
			if !bytes.Equal(actual, original) {
				t.Fatal("failed setup changed configuration")
			}
			if _, err := os.Stat(output + ".bak"); !os.IsNotExist(err) {
				t.Fatal("failed setup touched backup")
			}
			// Empty and invalid answers must not silently accept SNI either.
			text, err := executeGuidedTest(srv.URL, output, "none\n\n\nn\n1\n1\n\nnot-a-domain\nowned.example.test\n\nn\n")
			if err != nil {
				t.Fatalf("%v\n%s", err, text)
			}
			if readSetupCert(t, output).CertDomain != "owned.example.test" {
				t.Fatal("manual domain lost")
			}
		})
	}
}

func writeSavedSetupCert(t *testing.T, output, panelURL string, cert conf.CertConfig) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"Nodes": []map[string]any{{"ApiHost": panelURL, "NodeType": "anytls", "NodeID": 1, "CertConfig": cert}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(output, data, 0600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCertificateConflictRequiresChoiceAndKeepsDNSCredentials(t *testing.T) {
	srv := certificatePanel(t, "anytls", `{"host":"owned.example.test","server_name":"old-sni.example.test","server_port":443,"tls":1}`)
	for _, row := range []struct{ choice, want string }{{"1", "owned.example.test"}, {"2", "old-sni.example.test"}, {"3\norigin.example.test", "origin.example.test"}} {
		t.Run(row.want, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "config.json")
			saved := conf.CertConfig{CertMode: "dns", CertDomain: "old-sni.example.test", CertFile: "/shared/old.pem", KeyFile: "/shared/old.key", Provider: "cloudflare", AccountDir: "/shared/accounts", Email: "admin@example.test", DNSEnv: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "fictional-dns-secret"}}
			original := writeSavedSetupCert(t, output, srv.URL, saved)
			text, err := executeGuidedTest(srv.URL, output, "none\n\n\nn\n1\n1\n\n"+row.choice+"\n\nn\n")
			if err != nil {
				t.Fatalf("%v\n%s", err, text)
			}
			if !strings.Contains(text, "Choose 1–3") {
				t.Fatal("Enter silently resolved a conflicting certificate domain")
			}
			cert := readSetupCert(t, output)
			if cert.CertDomain != row.want || cert.CertMode != "dns" || cert.Provider != saved.Provider || cert.Email != saved.Email || cert.AccountDir != saved.AccountDir || cert.DNSEnv["CLOUDFLARE_DNS_API_TOKEN"] != "fictional-dns-secret" {
				t.Fatalf("renewal settings lost: domain=%s mode=%s", cert.CertDomain, cert.CertMode)
			}
			if row.want == saved.CertDomain {
				if cert.CertFile != saved.CertFile || cert.KeyFile != saved.KeyFile {
					t.Fatal("unchanged domain paths replaced")
				}
			} else if cert.CertFile != filepath.Join(filepath.Dir(output), "certs", row.want, "fullchain.pem") || cert.KeyFile == saved.KeyFile {
				t.Fatal("domain change would overwrite another node's certificate")
			}
			backup, _ := os.ReadFile(output + ".bak")
			if !bytes.Equal(backup, original) {
				t.Fatal("backup differs from prior config")
			}
			if strings.Contains(text, "fictional-dns-secret") {
				t.Fatal("printed DNS secret")
			}
		})
	}
}

func TestCertificateEditAndExplicitOverrideRetargetManagedFiles(t *testing.T) {
	srv := certificatePanel(t, "anytls", `{"host":"owned.example.test","server_name":"borrowed.example.test","server_port":443,"tls":1}`)
	for _, explicit := range []bool{false, true} {
		output := filepath.Join(t.TempDir(), "config.json")
		saved := conf.CertConfig{CertMode: "dns", CertDomain: "owned.example.test", CertFile: "/shared/old.pem", KeyFile: "/shared/old.key", Provider: "cloudflare", DNSEnv: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "fictional-dns-secret"}}
		writeSavedSetupCert(t, output, srv.URL, saved)
		c := newConfigureCommand()
		args := []string{"--guided", "--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--output", output}
		input := "none\n\n\nn\n1\n1\ne\n\norigin.example.test\n\n\n\n\nn\n"
		if explicit {
			args = append(args, "--cert-domain", "origin.example.test")
			input = "none\n\n\nn\n1\n1\n\nn\n"
		}
		c.SetArgs(args)
		c.SetIn(strings.NewReader(input))
		var text bytes.Buffer
		c.SetOut(&text)
		c.SetErr(&text)
		if err := c.Execute(); err != nil {
			t.Fatalf("explicit=%v: %v\n%s", explicit, err, text.String())
		}
		cert := readSetupCert(t, output)
		if cert.CertDomain != "origin.example.test" || cert.CertMode != "dns" || cert.DNSEnv["CLOUDFLARE_DNS_API_TOKEN"] != "fictional-dns-secret" || cert.CertFile == saved.CertFile {
			t.Fatal("domain override reused old paths or discarded renewal credentials")
		}
	}
}

func TestCertificateFileValidatesChosenDomainNotSNI(t *testing.T) {
	// A real certificate covering the owned node must pass despite a different
	// advertised SNI. One covering only SNI must fail without modifying config.
	srv := certificatePanel(t, "anytls", `{"host":"owned.example.test","server_name":"borrowed.example.test","server_port":443,"tls":1}`)
	for _, name := range []string{"owned.example.test", "borrowed.example.test"} {
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(dir, "config.json")
		// Explicit file-mode flags must win over an old saved DNS configuration.
		original := writeSavedSetupCert(t, output, srv.URL, conf.CertConfig{CertMode: "dns", CertDomain: "owned.example.test", CertFile: "/shared/old.pem", KeyFile: "/shared/old.key", Provider: "cloudflare"})
		c := newConfigureCommand()
		c.SetArgs([]string{"--guided", "--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--output", output, "--cert-mode", "file", "--cert-file", certPath, "--key-file", keyPath})
		c.SetIn(strings.NewReader("none\n\n\nn\n1\n1\n\nn\n"))
		var text bytes.Buffer
		c.SetOut(&text)
		c.SetErr(&text)
		err = c.Execute()
		if name == "owned.example.test" {
			if err != nil {
				t.Fatalf("owned cert rejected: %v\n%s", err, text.String())
			}
			if cert := readSetupCert(t, output); cert.CertDomain != name || cert.CertMode != "file" || cert.CertFile != certPath {
				t.Fatal("explicit file settings ignored")
			}
		} else {
			if err == nil || !strings.Contains(text.String(), "certificate does not cover") {
				t.Fatal("wrong SNI-only certificate accepted")
			}
			actual, _ := os.ReadFile(output)
			if !bytes.Equal(actual, original) {
				t.Fatal("wrong certificate replaced active config")
			}
		}
	}
}

func TestOldPanelSavedSNIDomainNeedsExplicitConfirmation(t *testing.T) {
	for _, host := range []string{"", "192.0.2.10"} {
		t.Run(host, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"host": host, "server_name": "old-sni.example.test", "server_port": 443, "tls": 1})
			srv := certificatePanel(t, "anytls", string(body))
			for _, ending := range []string{"\n", "\n2\nowned.example.test\n\nn\n"} {
				output := filepath.Join(t.TempDir(), "config.json")
				original := writeSavedSetupCert(t, output, srv.URL, conf.CertConfig{CertMode: "http", CertDomain: "old-sni.example.test", CertFile: "/shared/old.pem", KeyFile: "/shared/old.key"})
				text, err := executeGuidedTest(srv.URL, output, "none\n\n\nn\n1\n1\n"+ending)
				if !strings.Contains(text, "Choose 1–2") {
					t.Fatal("old SNI-derived domain was silently reused")
				}
				if ending == "\n" {
					if err == nil {
						t.Fatal("incomplete confirmation accepted")
					}
					actual, _ := os.ReadFile(output)
					if !bytes.Equal(actual, original) {
						t.Fatal("incomplete correction changed config")
					}
					if _, err := os.Stat(output + ".bak"); !os.IsNotExist(err) {
						t.Fatal("incomplete correction changed backup")
					}
				} else {
					if err != nil {
						t.Fatalf("%v\n%s", err, text)
					}
					if cert := readSetupCert(t, output); cert.CertDomain != "owned.example.test" || cert.CertFile == "/shared/old.pem" {
						t.Fatal("explicit correction not applied safely")
					}
				}
			}
		})
	}
}

func TestGuidedEmailOverridePreservesDNSRenewal(t *testing.T) {
	srv := certificatePanel(t, "anytls", `{"host":"owned.example.test","server_port":443,"tls":1}`)
	output := filepath.Join(t.TempDir(), "config.json")
	writeSavedSetupCert(t, output, srv.URL, conf.CertConfig{CertMode: "dns", CertDomain: "owned.example.test", CertFile: "/shared/old.pem", KeyFile: "/shared/old.key", Provider: "cloudflare", Email: "old@example.test", DNSEnv: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "fictional-dns-secret"}})
	c := newConfigureCommand()
	c.SetArgs([]string{"--guided", "--panel", srv.URL, "--api-key-env", "V2BX_TEST_API_KEY", "--output", output, "--acme-email", "new@example.test"})
	c.SetIn(strings.NewReader("none\n\n\nn\n1\n1\n\nn\n"))
	var text bytes.Buffer
	c.SetOut(&text)
	c.SetErr(&text)
	if err := c.Execute(); err != nil {
		t.Fatalf("%v\n%s", err, text.String())
	}
	cert := readSetupCert(t, output)
	if cert.Email != "new@example.test" || cert.CertMode != "dns" || cert.Provider != "cloudflare" || cert.DNSEnv["CLOUDFLARE_DNS_API_TOKEN"] != "fictional-dns-secret" || cert.CertFile != "/shared/old.pem" {
		t.Fatal("updating email replaced independent certificate settings")
	}
}
