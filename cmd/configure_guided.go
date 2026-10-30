package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/spf13/cobra"
)

var setupCoreProtocols = map[string][]string{
	"sing":        {"anytls", "vmess", "vless", "trojan", "shadowsocks", "hysteria", "tuic"},
	"xray":        {"vless", "vmess", "trojan", "shadowsocks"},
	"hysteria2":   {"hysteria"},
	"mdns":        {"mdns"},
	"trusttunnel": {"trusttunnel"},
	"mihomo":      {"http", "socks5", "mieru", "shadowquic", "sudoku", "snell", "vmess", "vless", "trojan", "tuic", "hysteria2", "anytls", "trusttunnel"},
}

func validSetupCore(core string) bool { return core == "auto" || setupCoreProtocols[core] != nil }

func setupCoreSupports(core, protocol string) bool {
	if core == "hysteria2" {
		return protocol == "hysteria2"
	}
	if core == "sing" && protocol == "hysteria2" {
		return true
	}
	for _, candidate := range setupCoreProtocols[core] {
		if protocol == candidate {
			return true
		}
	}
	return false
}

func validateSetupCore(core string, info *panel.NodeInfo) error {
	if !setupCoreSupports(core, info.Type) {
		return fmt.Errorf("%s core cannot serve %s", core, info.Type)
	}
	if core == "sing" && info.Type == "vless" && info.VAllss != nil && info.VAllss.Encryption != "" {
		return fmt.Errorf("VLESS encryption requires Xray; select Xray or change the node settings in the panel")
	}
	return nil
}

func resolveSetupCore(core string, info *panel.NodeInfo) string {
	if core != "auto" {
		return core
	}
	if info.Type == "http" || info.Type == "socks5" || info.Type == "mieru" || info.Type == "shadowquic" || info.Type == "sudoku" || info.Type == "snell" {
		return "mihomo"
	}
	if info.Type == "mdns" || info.Type == "trusttunnel" {
		return info.Type
	}
	if info.Type == "vless" && info.VAllss != nil && info.VAllss.Encryption != "" {
		return "xray"
	}
	if info.Security == panel.Tls && ((info.Trojan != nil && (info.Trojan.Network == "" || info.Trojan.Network == "tcp")) || (info.VAllss != nil && info.Type == "vless" && info.VAllss.Network == "tcp" && info.VAllss.Encryption == "")) {
		return "xray"
	}
	return "sing"
}

type setupPrompter struct {
	reader *bufio.Reader
	out    io.Writer
}

func (p setupPrompter) ask(label, fallback string) (string, error) {
	if fallback != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", label, fallback)
	} else {
		fmt.Fprintf(p.out, "%s: ", label)
	}
	line, err := p.reader.ReadString('\n')
	if err != nil && !(err == io.EOF && len(line) > 0) {
		return "", fmt.Errorf("wizard input ended; existing configuration was kept")
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return fallback, nil
	}
	return line, nil
}

func (p setupPrompter) choice(label string, choices []string, fallback int) (int, error) {
	for {
		defaultValue := ""
		if fallback > 0 {
			defaultValue = strconv.Itoa(fallback)
		}
		value, err := p.ask(label, defaultValue)
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(value)
		if err == nil && n > 0 && n <= len(choices) {
			return n - 1, nil
		}
		fmt.Fprintf(p.out, "Choose 1–%d | یک گزینه معتبر انتخاب کنید\n", len(choices))
	}
}

func (p setupPrompter) yesNo(label string) (bool, error) {
	for {
		answer, err := p.ask(label, "N")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.out, "Use y or n | از y یا n استفاده کنید")
	}
}

type setupPreferences struct {
	blocked                []string
	logLevel, coreLogLevel string
	mux                    bool
}

func (p setupPrompter) preferences() (setupPreferences, error) {
	var prefs setupPreferences
	blocked, err := p.ask("Block countries (sing core), comma separated; 'none' to disable | کشورهای مسدود", "ir")
	if err != nil {
		return prefs, err
	}
	if !strings.EqualFold(blocked, "none") {
		for _, country := range strings.Split(blocked, ",") {
			country = strings.ToLower(strings.TrimSpace(country))
			if len(country) != 2 || country[0] < 'a' || country[0] > 'z' || country[1] < 'a' || country[1] > 'z' {
				return prefs, fmt.Errorf("country codes must have two letters, e.g. ir,cn")
			}
			prefs.blocked = append(prefs.blocked, country)
		}
	}
	for _, item := range []struct {
		label, fallback string
		target          *string
	}{{"V2bX log level (debug/info/warn/error)", "info", &prefs.logLevel}, {"Core connection-log level (debug/info/warn/error)", "warn", &prefs.coreLogLevel}} {
		for {
			value, err := p.ask(item.label, item.fallback)
			if err != nil {
				return prefs, err
			}
			if value == "debug" || value == "info" || value == "warn" || value == "error" {
				*item.target = value
				break
			}
			fmt.Fprintln(p.out, "Use debug, info, warn or error.")
		}
	}
	fmt.Fprintln(p.out, "Enable multiplexing (smux)? | فعال کردن مالتی‌پلکس؟\n  vmess / vless / trojan / shadowsocks; AnyTLS and Hysteria have built-in mux.")
	prefs.mux, err = p.yesNo("Enable? | فعال شود؟")
	return prefs, err
}

func guidedPanelConfig(cmd *cobra.Command, defaults configureOptions, key string, reader *bufio.Reader) (map[string]any, []string, error) {
	p := setupPrompter{reader: reader, out: cmd.OutOrStdout()}
	// Reuse the headless URL/key validation before any discovery request.
	if err := validateSetupPanel(defaults.panel, key); err != nil {
		return nil, nil, err
	}
	prefs, err := p.preferences()
	if err != nil {
		return nil, nil, err
	}
	var cores, nodes []map[string]any
	var summaries []string
	seenCores, seenNodes := map[string]bool{}, map[string]bool{}
	coreNames := []string{"sing", "xray", "hysteria2", "mdns", "trusttunnel", "mihomo"}
	for number := 1; ; {
		fmt.Fprintf(p.out, "\n━━━ Node %d | نود %d ━━━\n", number, number)
		var id int
		for {
			value, err := p.ask("Node ID | شناسه نود", "")
			if err != nil {
				return nil, nil, err
			}
			id, err = strconv.Atoi(value)
			if err == nil && id > 0 {
				break
			}
			fmt.Fprintln(p.out, "Node ID must be positive | شناسه باید عدد مثبت باشد")
		}
		fmt.Fprintln(p.out, "Core for this node | هسته این نود:\n  1. sing-box (AnyTLS, VMess, VLESS, Trojan, Shadowsocks, Hysteria, TUIC)\n  2. Xray (VLESS, VMess, Trojan, Shadowsocks)\n  3. Hysteria2 (dedicated | اختصاصی)\n  4. MDNS\n  5. TrustTunnel\n  6. Mihomo fork (server | سمت سرور)")
		fallback := 1
		for i, core := range coreNames {
			if core == defaults.core {
				fallback = i + 1
			}
		}
		chosen, err := p.choice("Core | هسته", coreNames, fallback)
		if err != nil {
			return nil, nil, err
		}
		core := coreNames[chosen]
		fmt.Fprintln(p.out, "Detecting from panel… | شناسایی از پنل…")
		ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
		found, err := panel.DiscoverNodeConfigs(ctx, conf.ApiConfig{APIHost: defaults.panel, Key: key, NodeID: id, Timeout: 6}, setupCoreProtocols[core])
		cancel()
		if err != nil {
			if errors.Is(err, panel.ErrNoNode) {
				if hint := otherCoreHint(cmd.Context(), defaults.panel, key, id, core, coreNames); hint != "" {
					err = fmt.Errorf("%w\n%s", err, hint)
				}
			}
			if retry, inputErr := retrySetupNode(p, err); inputErr != nil {
				return nil, nil, inputErr
			} else if !retry {
				return nil, nil, err
			}
			continue
		}
		selected := found[0]
		if len(found) > 1 {
			fmt.Fprintln(p.out, "This ID exists in multiple protocol tables; choose the intended node | این شناسه در چند پروتکل وجود دارد")
			labels := make([]string, len(found))
			for i, candidate := range found {
				labels[i] = candidate.Type
				fmt.Fprintf(p.out, "  %d. %s — port %d — %s\n", i+1, candidate.Type, candidate.Common.ServerPort, panelCertificateDomain(candidate))
			}
			index, err := p.choice("Node type | نوع نود", labels, 0)
			if err != nil {
				return nil, nil, err
			}
			selected = found[index]
		}
		if err := validateSetupCore(core, selected); err != nil {
			if retry, inputErr := retrySetupNode(p, err); inputErr != nil {
				return nil, nil, inputErr
			} else if !retry {
				return nil, nil, err
			}
			continue
		}
		label := fmt.Sprintf("%s:%d", selected.Type, selected.Id)
		if seenNodes[label] {
			return nil, nil, fmt.Errorf("duplicate node %s; existing configuration was kept", label)
		}
		o := defaults
		o.nodes, o.core, o.nodeCores, o.detectedNode = label, core, nil, selected
		if selected.Type == "shadowquic" && core == "mihomo" && o.mihomoJLSAddr == "" {
			o.mihomoJLSAddr, err = p.ask("ShadowQUIC JLS decoy host:port | نشانی سرویس QUIC استتار", "")
			if err != nil {
				return nil, nil, err
			}
			o.mihomoJLSSNI, err = p.ask("JLS decoy SNI | نام دامنهٔ سرویس استتار", "")
			if err != nil {
				return nil, nil, err
			}
		}

		o.existingCert = existingSetupCertificate(o.output, o.panel, selected)
		applySetupCertificateFlags(&o)
		fmt.Fprintf(p.out, "Node host | آدرس نود: %s\n", firstNonempty(panelCertificateDomain(selected), "(not provided / ارسال نشده)"))
		if sni := panelTLSName(selected); sni != "" {
			fmt.Fprintf(p.out, "Panel SNI | SNI پنل: %s\n", sni)
		}
		domain, err := chooseSetupCertificateDomain(p, o, selected)
		if err != nil {
			return nil, nil, err
		}
		o.certDomain = domain
		var config map[string]any
		var lines []string
		for {
			fmt.Fprintf(p.out, "Detected | شناسایی شد: %s — core=%s — port=%d — %s\n", label, core, selected.Common.ServerPort, setupSecuritySummary(selected, o))
			if sni := panelTLSName(selected); selected.Security == panel.Tls && selected.Type != "trusttunnel" && sni != "" && !sameSetupDomain(sni, o.certDomain) {
				fmt.Fprintln(p.out, "SNI differs from the certificate domain. The client's verification name must be covered by the certificate | SNI متفاوت است؛ نام مورد بررسی کلاینت باید در گواهی باشد. تنظیم SNI پنل را بررسی کنید")
			}
			answer, err := p.ask("Continue [Enter], edit [e], cancel [n] | ادامه با Enter، ویرایش e، لغو n", "Enter")
			if err != nil {
				return nil, nil, err
			}
			switch strings.ToLower(answer) {
			case "n", "no", "q":
				return nil, nil, fmt.Errorf("wizard cancelled; existing configuration was kept")
			case "e", "edit":
				if err := editSetupNode(p, &o, selected); err != nil {
					return nil, nil, err
				}
				continue
			case "enter", "y", "yes":
			default:
				fmt.Fprintln(p.out, "Use Enter, e or n.")
				continue
			}
			config, lines, err = buildPanelConfig(o, key, nil)
			if err == nil {
				break
			}
			fmt.Fprintf(p.out, "Settings need correction | تنظیمات نیاز به اصلاح دارد: %s\n", err)
			if err := editSetupNode(p, &o, selected); err != nil {
				return nil, nil, err
			}
		}
		for _, entry := range config["Cores"].([]map[string]any) {
			if !seenCores[core] {
				entry["Log"] = map[string]any{"Level": prefs.coreLogLevel}
				if core == "xray" && prefs.coreLogLevel == "warn" {
					entry["Log"] = map[string]any{"Level": "warning"}
				}
				if core == "sing" {
					entry["BlockedCountries"] = prefs.blocked
				}
				cores = append(cores, entry)
				seenCores[core] = true
			}
		}
		for _, entry := range config["Nodes"].([]map[string]any) {
			if prefs.mux && core == "sing" && (selected.Type == "vmess" || selected.Type == "vless" || selected.Type == "trojan" || selected.Type == "shadowsocks") {
				entry["SingOptions"] = map[string]any{"MultiplexConfig": map[string]bool{"Enable": true}}
			}
			nodes = append(nodes, entry)
		}
		seenNodes[label] = true
		summaries = append(summaries, lines...)
		more, err := p.yesNo("Add another node? | نود دیگری اضافه کنید؟")
		if err != nil {
			return nil, nil, err
		}
		if !more {
			break
		}
		number++
	}
	return map[string]any{"Log": map[string]string{"Level": prefs.logLevel, "Output": ""}, "Cores": cores, "Nodes": nodes}, summaries, nil
}

// otherCoreHint names the cores that serve this ID's node when the chosen core
// serves none of its protocols, as when a Mieru node is looked up on sing-box.
func otherCoreHint(ctx context.Context, panelURL, key string, id int, chosen string, coreNames []string) string {
	probed := map[string]bool{}
	for _, protocol := range setupCoreProtocols[chosen] {
		probed[protocol] = true
	}
	var others []string
	for _, core := range coreNames {
		for _, protocol := range setupCoreProtocols[core] {
			if !probed[protocol] {
				probed[protocol] = true
				others = append(others, protocol)
			}
		}
	}
	if len(others) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	found, err := panel.DiscoverNodeConfigs(ctx, conf.ApiConfig{APIHost: panelURL, Key: key, NodeID: id, Timeout: 6}, others)
	if err != nil {
		return ""
	}
	var hints []string
	for _, info := range found {
		var cores []string
		for i, core := range coreNames {
			if validateSetupCore(core, info) == nil {
				cores = append(cores, fmt.Sprintf("%d (%s)", i+1, core))
			}
		}
		if len(cores) > 0 {
			hints = append(hints, fmt.Sprintf("ID %d is a %s node: choose core %s | این شناسه یک نود %s است؛ هستهٔ %s را انتخاب کنید", id, info.Type, strings.Join(cores, " or "), info.Type, strings.Join(cores, " یا ")))
		}
	}
	return strings.Join(hints, "\n")
}

func retrySetupNode(p setupPrompter, cause error) (bool, error) {
	fmt.Fprintf(p.out, "Could not configure this node | تنظیم این نود انجام نشد: %s\n", cause)
	for {
		answer, err := p.ask("Retry ID/core [Enter], cancel [n] | ورود دوباره شناسه/هسته با Enter، لغو n", "Enter")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "enter", "y", "yes":
			return true, nil
		case "n", "no", "q":
			return false, nil
		}
	}
}

func setupSecuritySummary(info *panel.NodeInfo, o configureOptions) string {
	if info.Type == "trusttunnel" && o.core != "mihomo" {
		return "certificate managed by TrustTunnel / گواهی تحت مدیریت TrustTunnel"
	}
	switch info.Security {
	case panel.Reality:
		return "REALITY; no certificate required / بدون نیاز به گواهی"
	case panel.Tls:
		if o.existingCert != nil {
			return "TLS; certificate domain=" + o.certDomain + "; saved renewal settings / تنظیمات تمدید ذخیره‌شده"
		}
		mode := o.certMode
		if mode == "auto" {
			mode = "http"
			if o.provider != "" {
				mode = "dns"
			}
		}
		switch mode {
		case "dns":
			return "TLS; certificate domain=" + o.certDomain + "; DNS-01 automatic certificate / گواهی خودکار DNS"
		case "file":
			return "TLS; certificate domain=" + o.certDomain + "; provided certificate files / فایل گواهی موجود"
		default:
			return "TLS; certificate domain=" + o.certDomain + "; HTTP-01 automatic issuance/renewal (port 80 + DNS required) / صدور و تمدید خودکار"
		}
	default:
		return "no TLS certificate required / بدون نیاز به گواهی TLS"
	}
}

func editSetupNode(p setupPrompter, o *configureOptions, info *panel.NodeInfo) error {
	value, err := p.ask("Listen IP | آدرس شنود", o.listen)
	if err != nil {
		return err
	}
	if net.ParseIP(value) == nil {
		return fmt.Errorf("invalid listen IP")
	}
	o.listen = value
	if info.Security != panel.Tls || info.Type == "trusttunnel" {
		return nil
	}
	original := o.existingCert
	if original != nil {
		c := original
		o.certFile, o.keyPath, o.provider, o.email, o.webroot = c.CertFile, c.KeyFile, c.Provider, c.Email, c.HTTPWebRoot
	}
	o.existingCert = nil
	if o.certDomain, err = p.ask("Certificate domain | دامنه گواهی", o.certDomain); err != nil {
		return err
	}
	fmt.Fprintln(p.out, "Certificate mode | روش گواهی:\n  1. HTTP-01 (automatic; port 80 + DNS)\n  2. DNS-01 (DNS provider credentials)\n  3. File (existing certificate/key)")
	fallback := 1
	if o.certMode == "dns" {
		fallback = 2
	} else if o.certMode == "file" {
		fallback = 3
	}
	choice, err := p.choice("Mode | روش", []string{"http", "dns", "file"}, fallback)
	if err != nil {
		return err
	}
	o.certMode = []string{"http", "dns", "file"}[choice]
	if o.certMode == "dns" {
		if o.provider, err = p.ask("DNS provider", firstNonempty(o.provider, "cloudflare")); err != nil {
			return err
		}
		if o.dnsEnvFile, err = p.ask("DNS credentials JSON file (0600) | فایل مشخصات DNS", o.dnsEnvFile); err != nil {
			return err
		}
	}
	if o.certMode == "http" {
		if o.webroot, err = p.ask("HTTP webroot, or '-' for built-in listener | مسیر وب‌سرور موجود", firstNonempty(o.webroot, "-")); err != nil {
			return err
		}
		if o.webroot == "-" {
			o.webroot = ""
		}
	}
	if o.certMode == "file" {
		if o.certFile, err = p.ask("Certificate file | فایل گواهی", o.certFile); err != nil {
			return err
		}
		if o.keyPath, err = p.ask("Private-key file | فایل کلید خصوصی", o.keyPath); err != nil {
			return err
		}
		if o.certFile, err = filepath.Abs(o.certFile); err != nil {
			return err
		}
		if o.keyPath, err = filepath.Abs(o.keyPath); err != nil {
			return err
		}
	}
	if original != nil {
		copy := *original
		copy.CertMode, copy.Provider, copy.HTTPWebRoot = o.certMode, o.provider, o.webroot
		if original.CertMode == "file" && o.certMode != "file" {
			copy.CertFile, copy.KeyFile = "", ""
		}
		if o.certMode == "file" {
			copy.CertFile, copy.KeyFile = o.certFile, o.keyPath
		}
		o.existingCert = &copy
	}
	return nil
}

func firstNonempty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

// Read only the local JSON shape, without resolving Include URLs or starting
// ACME. Preserve managed certificate paths and renewal credentials on re-setup.
func existingSetupCertificate(path, panelURL string, info *panel.NodeInfo) *conf.CertConfig {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var config struct {
		Nodes []struct {
			ApiHost, NodeType string
			NodeID            int
			CertConfig        *conf.CertConfig
			Options           struct{ CertConfig *conf.CertConfig }
		}
	}
	if json.NewDecoder(io.LimitReader(f, 2<<20)).Decode(&config) != nil {
		return nil
	}
	for _, node := range config.Nodes {
		if node.NodeID != info.Id || node.NodeType != info.Type || strings.TrimRight(node.ApiHost, "/") != strings.TrimRight(panelURL, "/") {
			continue
		}
		cert := node.CertConfig
		if node.Options.CertConfig != nil {
			cert = node.Options.CertConfig
		}
		if cert != nil && (cert.CertMode == "http" || cert.CertMode == "dns" || cert.CertMode == "file") && cert.CertFile != "" && cert.KeyFile != "" {
			cert.ExpandPaths()
			return cert
		}
	}
	return nil
}
