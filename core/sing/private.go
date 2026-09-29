package sing

import (
	"fmt"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// privateDestinationRules keep subscribers inside the internet.
//
// With no route rules at all - which is what the shipped sing_origin.json
// has - a subscriber could open connections through the node to 127.0.0.1
// and its private networks: the node's own services (the TrustTunnel
// endpoint's metrics port serves and resets every user's traffic counters),
// the hosting provider's internal network and its metadata address. The
// July log sample also shows clients sending junk there, such as an Iranian
// ISP's 10.x addresses, each held open until the dial timed out.
//
// Three rules, first in the list:
//  1. a literal private address is refused at once, before any DNS work;
//  2. a domain is resolved here - the same single lookup the dial would make,
//     whose answers the dial then reuses - so that
//  3. a name that resolves to a private address is refused too. Without this
//     step `localtest.me` and friends walk straight past rule 1.
var privateDestinationRules = []string{
	`{"ip_is_private":true,"action":"reject"}`,
	`{"action":"resolve"}`,
	`{"ip_is_private":true,"action":"reject"}`,
}

// addPrivateDestinationRules puts the rules above in front of any the node's
// config already has.
func addPrivateDestinationRules(options *option.Options) error {
	if options.Route == nil {
		options.Route = &option.RouteOptions{}
	}
	rules := make([]option.Rule, 0, len(privateDestinationRules)+len(options.Route.Rules))
	for _, raw := range privateDestinationRules {
		var rule option.Rule
		if err := json.Unmarshal([]byte(raw), &rule); err != nil {
			return fmt.Errorf("private destination rule %s: %w", raw, err)
		}
		rules = append(rules, rule)
	}
	options.Route.Rules = append(rules, options.Route.Rules...)
	return nil
}

// addSniffRule puts a sniff action in front of every other route rule.
//
// Each node's listener asks for sniffing through the legacy inbound fields
// (SniffEnabled, SniffOverrideDestination), which sing-box 1.13 removed: the
// fields are still in the Go struct, so this compiled, but nothing reads them
// any more and sniffing was simply off. The panel's domain rules then only saw
// a client's own destination - an app that resolves names itself and connects
// to the IP walked past every one - and its protocol rules (bittorrent, tls,
// quic) never matched at all, the hook having no sniffed protocol to test.
//
// A rule action is how 1.13 sniffs. Nodes are added after the box starts, so
// the rule cannot name their inbounds and applies to every inbound; the
// per-node EnableSniff therefore no longer turns sniffing off for one node.
// The sniffed name is recorded, not dialled: the destination stays what the
// client asked for, and the hook checks the panel's rules against both.
// A sniff rule already in the node's config does no harm: sing-box skips a
// second sniff of the same connection, and ports it knows to be server-first.
func addSniffRule(options *option.Options) error {
	if options.Route == nil {
		options.Route = &option.RouteOptions{}
	}
	var rule option.Rule
	if err := json.Unmarshal([]byte(`{"action":"sniff"}`), &rule); err != nil {
		return fmt.Errorf("sniff rule: %w", err)
	}
	options.Route.Rules = append([]option.Rule{rule}, options.Route.Rules...)
	return nil
}
