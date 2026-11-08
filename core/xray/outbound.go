package xray

import (
	"fmt"

	"encoding/json"

	conf2 "github.com/PoriyaVali/V2bX/conf"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// buildOutbound builds a node's freedom outbound. Xray refuses its proxy
// inbounds' users loopback, private and link-local destinations; with
// allowPrivate (the core's AllowPrivateDestinations) a final rule lets them
// through, as the option does on the sing and Mihomo cores.
func buildOutbound(config *conf2.Options, tag string, allowPrivate bool) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = tag

	// Build Send IP address
	if config.SendIP != "" {
		outboundDetourConfig.SendThrough = &config.SendIP
	}

	// Freedom Protocol setting
	var domainStrategy = "Asis"
	if config.XrayOptions.EnableDNS {
		if config.XrayOptions.DNSType != "" {
			domainStrategy = config.XrayOptions.DNSType
		} else {
			domainStrategy = "UseIP"
		}
	}
	proxySetting := &conf.FreedomConfig{
		DomainStrategy: domainStrategy,
	}
	if allowPrivate {
		proxySetting.FinalRules = []*conf.FreedomFinalRuleConfig{{Action: "allow"}}
	}
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy config error: %s", err)
	}
	outboundDetourConfig.Settings = &setting
	return outboundDetourConfig.Build()
}
