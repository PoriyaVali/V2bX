package core

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/sirupsen/logrus/hooks/test"
)

// A node's panel rules are warned about only where its core does not apply
// them. The hysteria2 core's destination guard applies the domain, address
// and port rules and a UDP block; it was still warned about every rule, so
// an operator read that rules in force did nothing.
func TestWarnRulesNotEnforcedNamesOnlyRulesTheCoreSkips(t *testing.T) {
	applied := panel.Rules{
		Regexp:   []string{`blocked\.example`},
		Domain:   []string{"domain:example.org"},
		IP:       []string{"10.0.0.0/8"},
		Port:     []string{"25"},
		Protocol: []string{"udp"},
	}
	withProtocol := applied
	withProtocol.Protocol = []string{"udp", "bittorrent"}
	route := []panel.RouteRule{{Id: 1, Action: "route", Match: []string{"example.com"}}}
	for _, c := range []struct {
		name   string
		core   string
		rules  panel.Rules
		routes []panel.RouteRule
		warned int // the block_rules count warned about; -1 for no warning
	}{
		{"hysteria2, every rule its guard applies", "hysteria2", applied, nil, -1},
		{"hysteria2, a protocol it cannot sniff", "hysteria2", withProtocol, nil, 1},
		{"hysteria2, a route", "hysteria2", applied, route, 0},
		{"trusttunnel, every rule", "trusttunnel", applied, nil, 5},
		{"sing", "sing", withProtocol, nil, -1},
		{"xray", "xray", withProtocol, route, -1},
		{"mihomo", "mihomo", withProtocol, nil, -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			hook := test.NewGlobal()
			defer hook.Reset()
			warnRulesNotEnforced("node", c.core, &panel.NodeInfo{Rules: c.rules, RouteRules: c.routes})
			entries := hook.AllEntries()
			if c.warned < 0 {
				if len(entries) != 0 {
					t.Fatalf("warned %q", entries[0].Message)
				}
				return
			}
			if len(entries) != 1 {
				t.Fatalf("got %d log entries, want one warning", len(entries))
			}
			if got := entries[0].Data["block_rules"]; got != c.warned {
				t.Fatalf("block_rules = %v, want %d", got, c.warned)
			}
			if got := entries[0].Data["route_rules"]; got != len(c.routes) {
				t.Fatalf("route_rules = %v, want %d", got, len(c.routes))
			}
		})
	}
}
