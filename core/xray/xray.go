package xray

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"encoding/json/v2"

	"github.com/PoriyaVali/V2bX/common/decoy"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/core/xray/app/dispatcher"
	_ "github.com/PoriyaVali/V2bX/core/xray/distro/all"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

var _ vCore.Core = (*Xray)(nil)

func init() {
	vCore.RegisterCore("xray", New)
}

// Xray Structure
type Xray struct {
	access                    sync.Mutex
	Server                    *core.Instance
	ihm                       inbound.Manager
	ohm                       outbound.Manager
	dispatcher                *dispatcher.DefaultDispatcher
	users                     *UserMap
	nodeReportMinTrafficBytes map[string]int64
	// Outbound (and rule) tags each node's panel route rules installed.
	routeMu   sync.Mutex
	routeTags map[string][]string
	// Each TLS node's own decoy site (common/decoy), by node tag.
	decoysMu sync.Mutex
	decoys   map[string]*decoy.Site
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	if c == nil || c.XrayConfig == nil {
		return nil, fmt.Errorf("xray configuration is required")
	}
	server, err := getCore(c.XrayConfig)
	if err != nil {
		return nil, err
	}
	return &Xray{
		Server: server,
		users: &UserMap{
			uidMap: make(map[string]int),
		},
		nodeReportMinTrafficBytes: make(map[string]int64),
		routeTags:                 make(map[string][]string),
		decoys:                    make(map[string]*decoy.Site),
	}, nil
}

// accessLogPath maps the configured AccessPath onto xray's setting.
//
// xray reads an empty path as "print to the console", so a node that left it
// unset wrote one line per connection into the journal - whatever the log
// level, which governs only the error log. On a busy node that is a steady
// load on the journal and the disk, and a record of every destination every
// user visited. Unset now means off; "console" (or "stdout") asks for the old
// behaviour, and a file path works as before.
func accessLogPath(configured string) string {
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case "":
		return "none"
	case "console", "stdout":
		return ""
	}
	return configured
}

func parseConnectionConfig(c *conf.XrayConnectionConfig) (policy *coreConf.Policy) {
	policy = &coreConf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &c.Handshake,
		ConnectionIdle:    &c.ConnIdle,
		UplinkOnly:        &c.UplinkOnly,
		DownlinkOnly:      &c.DownlinkOnly,
		BufferSize:        &c.BufferSize,
	}
	return
}

func getCore(c *conf.XrayConfig) (server *core.Instance, err error) {
	if c.LogConfig == nil || c.ConnectionConfig == nil {
		return nil, fmt.Errorf("xray Log and XrayConnectionConfig must not be null")
	}
	oldAsset, hadAsset := os.LookupEnv("XRAY_LOCATION_ASSET")
	oldDNS, hadDNS := os.LookupEnv("XRAY_DNS_PATH")
	defer func() {
		if err != nil {
			for key, previous := range map[string]struct {
				value   string
				present bool
			}{
				"XRAY_LOCATION_ASSET": {oldAsset, hadAsset}, "XRAY_DNS_PATH": {oldDNS, hadDNS},
			} {
				if previous.present {
					_ = os.Setenv(key, previous.value)
				} else {
					_ = os.Unsetenv(key)
				}
			}
		}
	}()
	os.Setenv("XRAY_LOCATION_ASSET", c.AssetPath)
	// Log Config
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: accessLogPath(c.LogConfig.AccessPath),
		ErrorLog:  c.LogConfig.ErrorPath,
	}
	// DNS config
	coreDnsConfig := &coreConf.DNSConfig{}
	os.Setenv("XRAY_DNS_PATH", "")
	if c.DnsConfigPath != "" {
		data, err := os.ReadFile(c.DnsConfigPath)
		if err != nil {
			return nil, fmt.Errorf("read xray DNS config: %w", err)
		}
		if err := json.Unmarshal(data, coreDnsConfig); err != nil {
			return nil, fmt.Errorf("decode xray DNS config: %w", err)
		}
		os.Setenv("XRAY_DNS_PATH", c.DnsConfigPath)
	}
	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build xray DNS config: %w", err)
	}
	// Routing config
	coreRouterConfig := &coreConf.RouterConfig{}
	if c.RouteConfigPath != "" {
		data, err := os.ReadFile(c.RouteConfigPath)
		if err != nil {
			return nil, fmt.Errorf("read xray routing config: %w", err)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				return nil, fmt.Errorf("decode xray routing config: %w", err)
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build xray routing config: %w", err)
	}
	// Custom Inbound config
	var coreCustomInboundConfig []coreConf.InboundDetourConfig
	if c.InboundConfigPath != "" {
		data, err := os.ReadFile(c.InboundConfigPath)
		if err != nil {
			return nil, fmt.Errorf("read xray inbound config: %w", err)
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				return nil, fmt.Errorf("decode xray inbound config: %w", err)
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			return nil, fmt.Errorf("build xray inbound config: %w", err)
		}
		inBoundConfig = append(inBoundConfig, oc)
	}
	// Custom Outbound config
	var coreCustomOutboundConfig []coreConf.OutboundDetourConfig
	if c.OutboundConfigPath != "" {
		data, err := os.ReadFile(c.OutboundConfigPath)
		if err != nil {
			return nil, fmt.Errorf("read xray outbound config: %w", err)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				return nil, fmt.Errorf("decode xray outbound config: %w", err)
			}
		}
	}
	var outBoundConfig []*core.OutboundHandlerConfig
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			return nil, fmt.Errorf("build xray outbound config: %w", err)
		}
		outBoundConfig = append(outBoundConfig, oc)
	}
	// Policy config
	levelPolicyConfig := parseConnectionConfig(c.ConnectionConfig)
	corePolicyConfig := &coreConf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*coreConf.Policy{0: levelPolicyConfig}
	policyConfig, err := corePolicyConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build xray policy config: %w", err)
	}
	// Build Xray conf
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err = core.New(config)
	if err != nil {
		return nil, fmt.Errorf("create xray instance: %w", err)
	}
	log.Info("Xray Core Version: ", core.Version())
	return server, nil
}

// Start the Xray
func (c *Xray) Start() error {
	c.access.Lock()
	defer c.access.Unlock()
	if err := c.Server.Start(); err != nil {
		return err
	}
	c.ihm = c.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	c.ohm = c.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	c.dispatcher = c.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	return nil
}

// Close  the core
func (c *Xray) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	c.ihm = nil
	c.ohm = nil
	c.dispatcher = nil
	err := c.Server.Close()
	c.decoysMu.Lock()
	for tag, d := range c.decoys {
		_ = d.Close()
		delete(c.decoys, tag)
	}
	c.decoysMu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

func (c *Xray) Protocols() []string {
	return []string{
		"vmess",
		"vless",
		"shadowsocks",
		"trojan",
	}
}

func (c *Xray) Type() string {
	return "xray"
}
