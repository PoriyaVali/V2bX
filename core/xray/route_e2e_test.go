package xray

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"encoding/json"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/xtls/xray-core/features/routing"
)

// loopbackFreedom is an outbound that reaches the loopback echo server; the
// default freedom outbound refuses private destinations.
const loopbackFreedom = `{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}`

const blackhole = `{"protocol":"blackhole"}`

func nodeRules(x *Xray, tag string) []string {
	var out []string
	router := x.Server.GetFeature(routing.RouterType()).(routing.Router)
	for _, r := range router.ListRule() {
		if strings.HasPrefix(r.GetRuleTag(), tag+"|") {
			out = append(out, r.GetRuleTag())
		}
	}
	return out
}

// The panel's route, route_ip and default_out rules send a node's traffic to
// outbounds of their own. The node ignored them; here they must decide where
// a real connection goes.
func TestXray_PanelRouteRulesSteerTraffic(t *testing.T) {
	echo := echoServer(t)

	t.Run("route_ip to a blackhole", func(t *testing.T) {
		_, _, port := xrayNodeWith(t, 0, func(n *panel.NodeInfo) {
			n.RouteRules = []panel.RouteRule{{Id: 1, Action: "route_ip", Match: []string{"127.0.0.0/8"}, Outbound: json.RawMessage(blackhole)}}
		})
		if c, ok := dialThrough(t, port, echo); ok {
			c.Close()
			t.Fatal("traffic matching route_ip was not sent to its outbound")
		}
	})

	t.Run("route_ip that does not match", func(t *testing.T) {
		_, _, port := xrayNodeWith(t, 0, func(n *panel.NodeInfo) {
			n.RouteRules = []panel.RouteRule{{Id: 1, Action: "route_ip", Match: []string{"10.0.0.0/8"}, Outbound: json.RawMessage(blackhole)}}
		})
		c, ok := dialThrough(t, port, echo)
		if !ok {
			t.Fatal("traffic that matches no rule was routed away")
		}
		c.Close()
	})

	t.Run("default_out after a specific rule", func(t *testing.T) {
		// The specific rule lets loopback through; everything else would go
		// to the blackhole. default_out must be tried last.
		_, _, port := xrayNodeWith(t, 0, func(n *panel.NodeInfo) {
			n.RouteRules = []panel.RouteRule{
				{Id: 1, Action: "route_ip", Match: []string{"127.0.0.0/8"}, Outbound: json.RawMessage(loopbackFreedom)},
				{Id: 2, Action: "default_out", Outbound: json.RawMessage(blackhole)},
			}
		})
		c, ok := dialThrough(t, port, echo)
		if !ok {
			t.Fatal("the specific rule did not take precedence over default_out")
		}
		c.Close()
	})

	t.Run("default_out alone", func(t *testing.T) {
		_, _, port := xrayNodeWith(t, 0, func(n *panel.NodeInfo) {
			n.RouteRules = []panel.RouteRule{{Id: 2, Action: "default_out", Outbound: json.RawMessage(blackhole)}}
		})
		if c, ok := dialThrough(t, port, echo); ok {
			c.Close()
			t.Fatal("default_out did not receive the node's traffic")
		}
	})

	t.Run("a broken outbound is skipped, the node keeps serving", func(t *testing.T) {
		x, tag, port := xrayNodeWith(t, 0, func(n *panel.NodeInfo) {
			n.RouteRules = []panel.RouteRule{
				{Id: 1, Action: "route_ip", Match: []string{"127.0.0.0/8"}, Outbound: json.RawMessage(`{"protocol":`)},
				{Id: 2, Action: "route_ip", Match: []string{"127.0.0.0/8"}, Outbound: json.RawMessage(`{"protocol":"no-such-protocol"}`)},
			}
		})
		if got := nodeRules(x, tag); len(got) != 0 {
			t.Fatalf("broken rules were installed: %q", got)
		}
		c, ok := dialThrough(t, port, echo)
		if !ok {
			t.Fatal("a broken route rule took the node down")
		}
		c.Close()
	})

	t.Run("DelNode removes the node's rules and outbounds", func(t *testing.T) {
		x, tag, _ := xrayNodeWith(t, 0, func(n *panel.NodeInfo) {
			n.RouteRules = []panel.RouteRule{
				{Id: 1, Action: "route_ip", Match: []string{"10.0.0.0/8"}, Outbound: json.RawMessage(blackhole)},
				{Id: 2, Action: "default_out", Outbound: json.RawMessage(blackhole)},
			}
		})
		if got := nodeRules(x, tag); len(got) != 2 {
			t.Fatalf("installed rules = %q, want 2", got)
		}
		if err := x.DelNode(tag); err != nil {
			t.Fatal(err)
		}
		if got := nodeRules(x, tag); len(got) != 0 {
			t.Fatalf("rules left behind after DelNode: %q", got)
		}
		for _, id := range []string{tag + "|route|1", tag + "|default_out|2"} {
			if x.ohm.GetHandler(id) != nil {
				t.Fatalf("outbound %s left behind after DelNode", id)
			}
		}
	})
}

// block_ip and block_port reach the xray dispatcher through the limiter.
func TestXray_PanelBlockRulesRefuseConnections(t *testing.T) {
	echo := echoServer(t)
	_, echoPort, _ := net.SplitHostPort(echo)
	for name, rules := range map[string]*panel.Rules{
		"block_ip":         {IP: []string{"127.0.0.1/32"}},
		"block_port":       {Port: []string{echoPort}},
		"block_port range": {Port: []string{"1-65535"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, tag, port := xrayNode(t, 0)
			l, err := limiter.GetLimiter(tag)
			if err != nil {
				t.Fatal(err)
			}
			_ = l.UpdateRule(rules)
			if c, ok := dialThrough(t, port, echo); ok {
				c.Close()
				t.Fatal("a connection the rule blocks went through")
			}
			_ = l.UpdateRule(&panel.Rules{Port: []string{strconv.Itoa(1)}})
			c, ok := dialThrough(t, port, echo)
			if !ok {
				t.Fatal("a connection no rule blocks was refused")
			}
			c.Close()
		})
	}
}
