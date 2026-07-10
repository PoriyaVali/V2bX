package sing

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"

	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

var _ vCore.Core = (*Sing)(nil)

type DNSConfig struct {
	Servers []map[string]interface{} `json:"servers"`
	Rules   []map[string]interface{} `json:"rules"`
}

type Sing struct {
	box                       *box.Box
	ctx                       context.Context
	hookServer                *HookServer
	router                    adapter.Router
	logFactory                log.Factory
	users                     *UserMap
	nodeReportMinTrafficBytes map[string]int64
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func init() {
	vCore.RegisterCore("sing", New)
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	ctx := context.Background()
	ctx = box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
	options := option.Options{}
	if len(c.SingConfig.OriginalPath) != 0 {
		if _, statErr := os.Stat(c.SingConfig.OriginalPath); os.IsNotExist(statErr) {
			if err := os.WriteFile(c.SingConfig.OriginalPath, []byte("{}"), 0644); err != nil {
				return nil, fmt.Errorf("create original config error: %s", err)
			}
		}
		data, err := os.ReadFile(c.SingConfig.OriginalPath)
		if err != nil {
			return nil, fmt.Errorf("read original config error: %s", err)
		}
		options, err = json.UnmarshalExtendedContext[option.Options](ctx, data)
		if err != nil {
			return nil, fmt.Errorf("unmarshal original config error: %s", err)
		}
	}
	options.Log = &option.LogOptions{
		Disabled:  c.SingConfig.LogConfig.Disabled,
		Level:     c.SingConfig.LogConfig.Level,
		Timestamp: c.SingConfig.LogConfig.Timestamp,
		Output:    c.SingConfig.LogConfig.Output,
	}
	options.NTP = &option.NTPOptions{
		Enabled:       c.SingConfig.NtpConfig.Enable,
		WriteToSystem: true,
		ServerOptions: option.ServerOptions{
			Server:     c.SingConfig.NtpConfig.Server,
			ServerPort: c.SingConfig.NtpConfig.ServerPort,
		},
	}
	// GeoIP country blocking via rule_set (sing-box 1.12+ removed legacy geoip field)
	if len(c.SingConfig.BlockedCountries) > 0 {
		const directTag = "direct"
		hasDirect := false
		for _, o := range options.Outbounds {
			if o.Tag == directTag {
				hasDirect = true
			}
		}
		if !hasDirect {
			options.Outbounds = append(options.Outbounds, option.Outbound{
				Tag:  directTag,
				Type: directTag,
			})
		}
		if options.Route == nil {
			options.Route = &option.RouteOptions{}
		}
		for _, country := range c.SingConfig.BlockedCountries {
			country = strings.ToLower(country)
			tag := "geoip-" + country
			// Remote rule_set — sing-box downloads and caches on first run
			ruleSetData := fmt.Sprintf(
				`{"tag":%q,"type":"remote","format":"binary","url":"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-%s.srs","download_detour":%q}`,
				tag, country, directTag,
			)
			var ruleSet option.RuleSet
			if err := json.Unmarshal([]byte(ruleSetData), &ruleSet); err == nil {
				options.Route.RuleSet = append(options.Route.RuleSet, ruleSet)
			}
			// Reject matching destinations at the route level with method
			// "drop" (silent). A reject action — not a block outbound — avoids
			// sing-box logging a per-connection ERROR ("open connection ...
			// using outbound/block: operation not permitted") for every blocked
			// attempt, which floods the journal when a client retries.
			ruleData := fmt.Sprintf(`{"rule_set":[%q],"action":"reject","method":"drop"}`, tag)
			var rule option.Rule
			if err := json.Unmarshal([]byte(ruleData), &rule); err == nil {
				options.Route.Rules = append([]option.Rule{rule}, options.Route.Rules...)
			}
		}
	}

	os.Setenv("SING_DNS_PATH", "")
	b, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return nil, err
	}
	hs := &HookServer{
		counter: sync.Map{},
	}
	b.Router().AppendTracker(hs)
	return &Sing{
		ctx:        b.Router().GetCtx(),
		box:        b,
		hookServer: hs,
		router:     b.Router(),
		logFactory: b.LogFactory(),
		users: &UserMap{
			uidMap: make(map[string]int),
		},
		nodeReportMinTrafficBytes: make(map[string]int64),
	}, nil
}

func (b *Sing) Start() error {
	return b.box.Start()
}

func (b *Sing) Close() error {
	return b.box.Close()
}

func (b *Sing) Protocols() []string {
	return []string{
		"vmess",
		"vless",
		"shadowsocks",
		"trojan",
		"tuic",
		"anytls",
		"hysteria",
		"hysteria2",
	}
}

func (b *Sing) Type() string {
	return "sing"
}
