package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/decoy"
	"github.com/PoriyaVali/V2bX/common/file"
	"github.com/PoriyaVali/V2bX/common/tlscert"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/node"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type configureOptions struct {
	panel, nodes, keyEnv, keyFile, output, core, listen                           string
	certMode, certDomain, certFile, keyPath, provider, dnsEnvFile, email, webroot string
	coverRoot, coverTitle                                                         string
	coverTCP                                                                      bool
}

func newConfigureCommand() *cobra.Command {
	o := configureOptions{}
	c := &cobra.Command{Use: "configure", Short: "Build node configuration from the panel | راه‌اندازی خودکار از پنل", Args: cobra.NoArgs}
	f := c.Flags()
	f.StringVar(&o.panel, "panel", "", "Panel URL")
	f.StringVar(&o.nodes, "nodes", "", "Comma-separated type:id entries, e.g. vless:1,mdns:2,hysteria2:3")
	f.StringVar(&o.keyEnv, "api-key-env", "", "Environment variable holding the panel API key")
	f.StringVar(&o.keyFile, "api-key-file", "", "File holding the panel API key")
	f.StringVar(&o.output, "output", "/etc/V2bX/config.json", "Configuration path; existing file is backed up with mode 0600")
	f.StringVar(&o.core, "core", "auto", "Proxy core: auto (protocol/TLS aware), sing, xray, hysteria2")
	f.StringVar(&o.listen, "listen-ip", "::", "Listener IP")
	f.StringVar(&o.certMode, "cert-mode", "auto", "auto (HTTP, or DNS with --dns-provider), http, dns, file")
	f.StringVar(&o.certDomain, "cert-domain", "", "Override the TLS domain inferred from the panel")
	f.StringVar(&o.certFile, "cert-file", "", "Existing certificate path for file mode")
	f.StringVar(&o.keyPath, "key-file", "", "Existing private-key path for file mode")
	f.StringVar(&o.provider, "dns-provider", "", "Lego DNS provider, e.g. cloudflare")
	f.StringVar(&o.dnsEnvFile, "dns-env-file", "", "JSON object containing DNS provider environment values")
	f.StringVar(&o.email, "acme-email", "", "Optional ACME account email")
	f.StringVar(&o.webroot, "http-webroot", "", "Existing web server document root for HTTP-01, avoiding a second port-80 listener")
	f.StringVar(&o.coverRoot, "cover-root", "", "Dedicated public static website directory for supported fallbacks/masquerades")
	f.StringVar(&o.coverTitle, "cover-title", "", "Optional title for the built-in cover site")
	f.BoolVar(&o.coverTCP, "cover-tcp", true, "Serve HTTPS on the TCP port of supported UDP TLS nodes when available")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		interactive := o.panel == "" && o.nodes == "" && o.keyEnv == "" && o.keyFile == ""
		reader := bufio.NewReader(cmd.InOrStdin())
		ask := func(prompt string) (string, error) {
			fmt.Fprint(cmd.OutOrStdout(), prompt)
			line, err := reader.ReadString('\n')
			if err != nil && !(err == io.EOF && len(line) > 0) {
				return "", fmt.Errorf("input required: %s", prompt)
			}
			return strings.TrimSpace(line), nil
		}
		var key string
		var err error
		if o.keyEnv != "" && o.keyFile != "" {
			return fmt.Errorf("choose either --api-key-env or --api-key-file")
		}
		if o.keyEnv != "" {
			key = os.Getenv(o.keyEnv)
		}
		if o.keyFile != "" {
			data, readErr := os.ReadFile(o.keyFile)
			if readErr != nil {
				return readErr
			}
			key = strings.TrimSpace(string(data))
		}
		if interactive {
			if o.panel, err = ask("Panel URL | آدرس پنل: "); err != nil {
				return err
			}
			if input, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(input.Fd())) {
				fmt.Fprint(cmd.OutOrStdout(), "API key | کلید API: ")
				secret, readErr := term.ReadPassword(int(input.Fd()))
				fmt.Fprintln(cmd.OutOrStdout())
				if readErr != nil {
					return readErr
				}
				key = string(secret)
			} else if key, err = ask("API key: "); err != nil {
				return err
			}
			if o.nodes, err = ask("Nodes (type:id,...) | نودها، مثال vless:1,mdns:2: "); err != nil {
				return err
			}
		}
		if o.output, err = filepath.Abs(o.output); err != nil {
			return err
		}
		if o.coverRoot != "" {
			if o.coverRoot, err = filepath.Abs(o.coverRoot); err != nil {
				return err
			}
		}
		if o.certFile != "" {
			if o.certFile, err = filepath.Abs(o.certFile); err != nil {
				return err
			}
		}
		if o.keyPath != "" {
			if o.keyPath, err = filepath.Abs(o.keyPath); err != nil {
				return err
			}
		}
		if o.webroot != "" {
			if o.webroot, err = filepath.Abs(o.webroot); err != nil {
				return err
			}
		}
		var domainPrompt func(string) (string, error)
		if interactive {
			domainPrompt = func(label string) (string, error) {
				return ask("TLS domain for " + label + " | دامنه گواهی: ")
			}
		}
		config, summaries, err := buildPanelConfig(o, strings.TrimSpace(key), domainPrompt)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		// Round-trip through the runtime parser before touching the old config.
		parsed := conf.New()
		if err := json.Unmarshal(data, parsed); err != nil {
			return fmt.Errorf("validate generated configuration: %w", err)
		}
		if err := savePanelConfig(o.output, append(data, '\n')); err != nil {
			return err
		}
		for _, line := range summaries {
			fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Saved | ذخیره شد: %s (0600)\n", o.output)
		fmt.Fprintln(cmd.OutOrStdout(), "HTTP certificates are obtained automatically at startup and renewed when due; DNS must point to this server and port 80 must be reachable. Use DNS mode when HTTP validation is unavailable.")
		return nil
	}
	return c
}

func init() { command.AddCommand(newConfigureCommand()) }

func buildPanelConfig(o configureOptions, key string, askDomain func(string) (string, error)) (map[string]any, []string, error) {
	u, err := url.Parse(o.panel)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, nil, fmt.Errorf("provide an http(s) panel URL without credentials or query parameters")
	}
	if key == "" {
		return nil, nil, fmt.Errorf("panel API key is required")
	}
	if net.ParseIP(o.listen) == nil {
		return nil, nil, fmt.Errorf("invalid listen IP")
	}
	if o.core != "auto" && o.core != "sing" && o.core != "xray" && o.core != "hysteria2" {
		return nil, nil, fmt.Errorf("unsupported core")
	}
	mode := o.certMode
	if mode == "auto" {
		mode = "http"
		if o.provider != "" {
			mode = "dns"
		}
	}
	if mode != "http" && mode != "dns" && mode != "file" {
		return nil, nil, fmt.Errorf("use http, dns or file certificates")
	}
	if mode == "dns" && o.provider == "" {
		return nil, nil, fmt.Errorf("DNS certificates require --dns-provider")
	}
	var dnsEnv map[string]string
	if o.dnsEnvFile != "" {
		data, err := os.ReadFile(o.dnsEnvFile)
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(data, &dnsEnv); err != nil {
			return nil, nil, fmt.Errorf("DNS environment file must contain a JSON string object")
		}
	}
	var nodes, cores []map[string]any
	cover := &decoy.Config{Root: o.coverRoot, Title: o.coverTitle, ServeTCP: &o.coverTCP}
	if o.coverRoot != "" || o.coverTitle != "" {
		if _, err := decoy.HandlerWithConfig("setup-validation", cover); err != nil {
			return nil, nil, err
		}
	}
	var summaries []string
	seenCores, seenNodes := map[string]bool{}, map[string]bool{}
	for _, entry := range strings.Split(o.nodes, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("nodes must use type:id, e.g. vless:1,mdns:2")
		}
		id, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || id < 1 {
			return nil, nil, fmt.Errorf("node ID must be positive")
		}
		apiConfig := conf.ApiConfig{APIHost: strings.TrimRight(o.panel, "/"), Key: key, NodeType: strings.TrimSpace(parts[0]), NodeID: id, Timeout: 10}
		client, err := panel.New(&apiConfig)
		if err != nil {
			return nil, nil, err
		}
		info, err := client.GetNodeInfo()
		if err != nil {
			return nil, nil, fmt.Errorf("read node %s: %w", entry, err)
		}
		if info == nil || info.Common == nil || info.Common.ServerPort < 1 || info.Common.ServerPort > 65535 {
			return nil, nil, fmt.Errorf("node %s: panel must return a complete configuration with a valid server port", entry)
		}
		label := fmt.Sprintf("%s:%d", info.Type, id)
		if seenNodes[label] {
			return nil, nil, fmt.Errorf("duplicate node %s", label)
		}
		seenNodes[label] = true
		core := o.core
		if core == "auto" {
			core = "sing"
			// Raw-TCP TLS needs a core with an unauthenticated HTTP fallback.
			if info.Security == panel.Tls && ((info.Trojan != nil && (info.Trojan.Network == "" || info.Trojan.Network == "tcp")) || (info.VAllss != nil && info.Type == "vless" && info.VAllss.Network == "tcp" && info.VAllss.Encryption == "")) {
				core = "xray"
			}
		}
		if info.Type == "mdns" || info.Type == "trusttunnel" {
			core = info.Type
		}
		if core == "xray" && info.Type != "vless" && info.Type != "vmess" && info.Type != "trojan" && info.Type != "shadowsocks" {
			return nil, nil, fmt.Errorf("xray cannot serve %s", info.Type)
		}
		if core == "hysteria2" && info.Type != "hysteria2" {
			return nil, nil, fmt.Errorf("hysteria2 core cannot serve %s", info.Type)
		}
		if !seenCores[core] {
			cores = append(cores, map[string]any{"Type": core})
			seenCores[core] = true
		}
		nodeConfig := map[string]any{"Core": core, "ApiHost": apiConfig.APIHost, "ApiKey": key, "NodeType": info.Type, "NodeID": id, "Timeout": 30, "ListenIP": o.listen}
		if o.coverRoot != "" || o.coverTitle != "" || !o.coverTCP {
			nodeConfig["Decoy"] = cover
		}
		certSummary := "certificate not required"
		if info.Security == panel.Tls && info.Type != "trusttunnel" {
			domain := o.certDomain
			if domain == "" {
				domain = panelCertificateDomain(info)
			}
			domain, err = setupCertificateDomain(domain, mode)
			if err != nil && askDomain != nil {
				domain, err = askDomain(label)
				if err == nil {
					domain, err = setupCertificateDomain(domain, mode)
				}
			}
			if err != nil {
				return nil, nil, fmt.Errorf("%s: cannot infer certificate domain; set the node hostname/SNI in Irboard or --cert-domain", label)
			}
			cert := conf.CertConfig{CertMode: mode, CertDomain: domain, Email: o.email, Provider: o.provider, DNSEnv: dnsEnv,
				AccountDir: filepath.Join(filepath.Dir(o.output), "certs", "accounts"), HTTPWebRoot: o.webroot,
				CertFile: filepath.Join(filepath.Dir(o.output), "certs", domain, "fullchain.pem"), KeyFile: filepath.Join(filepath.Dir(o.output), "certs", domain, "private.key")}
			if mode == "file" {
				if o.certFile == "" || o.keyPath == "" {
					return nil, nil, fmt.Errorf("file mode requires --cert-file and --key-file")
				}
				cert.CertFile, cert.KeyFile = o.certFile, o.keyPath
				loader, err := tlscert.New(cert.CertFile, cert.KeyFile, time.Minute)
				if err != nil {
					return nil, nil, fmt.Errorf("%s: invalid certificate files: %w", label, err)
				}
				pair, _ := loader.GetCertificate(nil)
				if pair.Leaf != nil {
					if err := pair.Leaf.VerifyHostname(domain); err != nil {
						return nil, nil, fmt.Errorf("%s: certificate does not cover the node hostname", label)
					}
				}
			} else {
				// Constructor validation is local; issuing is deferred to startup.
				if _, err := node.NewLego(&cert); err != nil {
					return nil, nil, fmt.Errorf("%s: %w", label, err)
				}
			}
			nodeConfig["CertConfig"] = cert
			certSummary = "TLS " + domain + " (" + mode + ")"
		} else if info.Type == "trusttunnel" {
			certSummary = "certificate managed by TrustTunnel using panel settings"
		}
		nodes = append(nodes, nodeConfig)
		summaries = append(summaries, label+" -> "+core+"; "+certSummary)
	}
	return map[string]any{"Log": map[string]string{"Level": "info", "Output": ""}, "Cores": cores, "Nodes": nodes}, summaries, nil
}

func setupCertificateDomain(value, mode string) (string, error) {
	if mode == "file" {
		if ip := net.ParseIP(value); ip != nil {
			return ip.String(), nil
		}
	}
	return tlscert.Domain(value)
}

func panelCertificateDomain(info *panel.NodeInfo) string {
	if info.VAllss != nil {
		if info.VAllss.TlsSettings.ServerName != "" {
			return info.VAllss.TlsSettings.ServerName
		}
		if info.VAllss.ServerName != "" {
			return info.VAllss.ServerName
		}
	}
	if info.Common.ServerName != "" {
		return info.Common.ServerName
	}
	return info.Common.Host
}

func savePanelConfig(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	previous, err := os.ReadFile(path)
	if err == nil {
		if err := file.WriteAtomic(path+".bak", previous, 0600); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return file.WriteAtomic(path, data, 0600)
}
