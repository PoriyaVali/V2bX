package xray

import (
	"fmt"
	"strconv"

	"encoding/json"

	"github.com/PoriyaVali/V2bX/api/panel"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// routeOutboundTag names the outbound, and the routing rule, that one panel
// route rule of a node installs. Both carry the node's tag, so another node's
// rules can never be removed or reused by mistake.
func routeOutboundTag(nodeTag string, r panel.RouteRule) string {
	if r.Action == "default_out" {
		return nodeTag + "|default_out|" + strconv.Itoa(r.Id)
	}
	return nodeTag + "|route|" + strconv.Itoa(r.Id)
}

// routeRuleJSON is the xray routing rule for one panel route rule: traffic
// entering through the node's inbound, matching the rule, goes to its
// outbound.
func routeRuleJSON(nodeTag, outTag string, r panel.RouteRule) ([]byte, error) {
	rule := map[string]any{
		"type":        "field",
		"inboundTag":  []string{nodeTag},
		"outboundTag": outTag,
		"ruleTag":     outTag,
	}
	switch r.Action {
	case "route":
		rule["domain"] = r.Match
	case "route_ip":
		rule["ip"] = r.Match
	case "default_out":
		// Everything else from this node: the inbound tag alone.
	default:
		return nil, fmt.Errorf("not a route action: %s", r.Action)
	}
	return json.Marshal(rule)
}

// addRouteRules installs the panel's route, route_ip and default_out rules
// for one node: an outbound of its own for each, built from the xray outbound
// object the panel holds, and a routing rule sending the node's matching
// traffic to it.
//
// The panel offered these and the node ignored them, so traffic an operator
// sent elsewhere - a region through another exit, everything through a
// chosen outbound - kept leaving through the node's own address.
//
// A rule that cannot be built is logged and skipped rather than failing the
// node: one bad outbound must not take every user on the node offline. The
// rules are appended after the ones from the route config file, which
// therefore still win.
func (c *Xray) addRouteRules(nodeTag string, rules []panel.RouteRule) {
	if len(rules) == 0 {
		return
	}
	router, ok := c.Server.GetFeature(routing.RouterType()).(routing.Router)
	if !ok || router == nil {
		log.WithField("tag", nodeTag).Warn("xray has no router; panel route rules not applied")
		return
	}
	var installed []string
	for _, r := range rules {
		outTag := routeOutboundTag(nodeTag, r)
		logger := log.WithFields(log.Fields{"tag": nodeTag, "route": r.Id, "action": r.Action})

		var ob coreConf.OutboundDetourConfig
		if err := json.Unmarshal(r.Outbound, &ob); err != nil {
			logger.Warn("Skipping a route rule whose outbound is not an xray outbound object: ", err)
			continue
		}
		ob.Tag = outTag
		obConfig, err := ob.Build()
		if err != nil {
			logger.Warn("Skipping a route rule whose outbound cannot be built: ", err)
			continue
		}

		raw, err := routeRuleJSON(nodeTag, outTag, r)
		if err != nil {
			logger.Warn("Skipping route rule: ", err)
			continue
		}
		routerConfig, err := (&coreConf.RouterConfig{RuleList: []json.RawMessage{raw}}).Build()
		if err != nil {
			logger.Warn("Skipping a route rule whose match cannot be used: ", err)
			continue
		}

		if err := c.addOutbound(obConfig); err != nil {
			logger.Warn("Skipping a route rule whose outbound cannot be added: ", err)
			continue
		}
		if err := router.AddRule(serial.ToTypedMessage(routerConfig), true); err != nil {
			_ = c.removeOutbound(outTag)
			logger.Warn("Skipping a route rule the router refused: ", err)
			continue
		}
		installed = append(installed, outTag)
	}
	if len(installed) > 0 {
		c.routeMu.Lock()
		c.routeTags[nodeTag] = installed
		c.routeMu.Unlock()
		log.WithField("tag", nodeTag).Infof("Applied %d panel route rule(s)", len(installed))
	}
}

// removeRouteRules takes out what addRouteRules installed for a node.
func (c *Xray) removeRouteRules(nodeTag string) {
	c.routeMu.Lock()
	tags := c.routeTags[nodeTag]
	delete(c.routeTags, nodeTag)
	c.routeMu.Unlock()
	if len(tags) == 0 {
		return
	}
	router, _ := c.Server.GetFeature(routing.RouterType()).(routing.Router)
	for _, t := range tags {
		if router != nil {
			if err := router.RemoveRule(t); err != nil {
				log.WithFields(log.Fields{"tag": nodeTag, "rule": t}).Warn("Remove route rule: ", err)
			}
		}
		if err := c.removeOutbound(t); err != nil {
			log.WithFields(log.Fields{"tag": nodeTag, "outbound": t}).Warn("Remove route outbound: ", err)
		}
	}
}
