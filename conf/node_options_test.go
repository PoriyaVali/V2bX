package conf

import (
	"encoding/json"
	"testing"
)

func parseNode(t *testing.T, raw string) NodeConfig {
	t.Helper()
	var n NodeConfig
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return n
}

// 🔴 A nested "SingOptions" block used to be parsed and then thrown away, so the
// values an operator wrote there never took effect and nothing said so. That is
// the shape the setup wizard emits, and the shape most people assume from the
// field name. A day was lost to it: ProxyProtocol was set there by hand, read
// back from the file as `true`, and the node behaved as `false`.
func TestNestedSingOptionsBlockIsHonoured(t *testing.T) {
	n := parseNode(t, `{"Core":"sing","NodeID":46,"NodeType":"anytls",
	                    "SingOptions":{"ProxyProtocol":true,"EnableTFO":true}}`)
	if n.Options.SingOptions == nil {
		t.Fatal("SingOptions is nil")
	}
	if !n.Options.SingOptions.ProxyProtocol {
		t.Error("ProxyProtocol from the nested block was discarded")
	}
	if !n.Options.SingOptions.TCPFastOpen {
		t.Error("EnableTFO from the nested block was discarded")
	}
}

// The top-level shape is what the code has always read; it must keep working,
// since live configs were edited into that shape to work around the bug.
func TestTopLevelSingOptionsStillWork(t *testing.T) {
	n := parseNode(t, `{"Core":"sing","NodeID":46,"NodeType":"anytls","ProxyProtocol":true}`)
	if !n.Options.SingOptions.ProxyProtocol {
		t.Error("top-level ProxyProtocol was lost")
	}
}

// When both are present the nested block is the more specific statement and wins.
func TestNestedWinsOverTopLevel(t *testing.T) {
	n := parseNode(t, `{"Core":"sing","NodeID":46,"ProxyProtocol":true,
	                    "SingOptions":{"ProxyProtocol":false}}`)
	if n.Options.SingOptions.ProxyProtocol {
		t.Error("nested false should override top-level true")
	}
}

// Defaults must survive a config that mentions neither - this is what every
// existing node relies on, and it is why the wizard's inert block was invisible.
func TestDefaultsSurviveWhenNothingIsSpecified(t *testing.T) {
	n := parseNode(t, `{"Core":"sing","NodeID":46,"NodeType":"anytls"}`)
	o := n.Options.SingOptions
	if o == nil {
		t.Fatal("SingOptions is nil")
	}
	if !o.SniffEnabled || !o.SniffOverrideDestination {
		t.Error("sniff defaults lost")
	}
	if !o.ProxyProtocol {
		// This assertion used to read the other way. It was changed on purpose:
		// opt-in cost a relay node weeks of reporting every tunnelled user as
		// 127.0.0.1, silently. See TestProxyProtocolIsOnWhenTheConfigDoesNotMentionIt.
		t.Error("ProxyProtocol must default on")
	}
	if !o.DecoyEnabled() {
		t.Error("the decoy must stay on by default")
	}
}

// A node that never mentions the core options at all, and one whose nested block
// is null, must not crash or wipe the defaults.
func TestMalformedOrAbsentNestedBlockIsIgnored(t *testing.T) {
	for name, raw := range map[string]string{
		"null":   `{"Core":"sing","NodeID":1,"SingOptions":null}`,
		"absent": `{"Core":"sing","NodeID":1}`,
	} {
		n := parseNode(t, raw)
		if n.Options.SingOptions == nil {
			t.Fatalf("%s: SingOptions is nil", name)
		}
		if !n.Options.SingOptions.SniffEnabled {
			t.Errorf("%s: defaults were wiped", name)
		}
	}
}

// The same discard affected xray nodes; both cores now overlay.
func TestNestedXrayOptionsBlockIsHonoured(t *testing.T) {
	n := parseNode(t, `{"Core":"xray","NodeID":9,"XrayOptions":{"EnableProxyProtocol":true}}`)
	if n.Options.XrayOptions == nil {
		t.Fatal("XrayOptions is nil")
	}
	if !n.Options.XrayOptions.EnableProxyProtocol {
		t.Error("EnableProxyProtocol from the nested block was discarded")
	}
}

// The wizard writes CertConfig as a SIBLING of the SingOptions block, not inside
// it - that is why certificates always worked while everything in the block did
// not. Pinned so a future tidy-up does not "helpfully" move it.
func TestCertConfigIsReadFromTheNodeTopLevel(t *testing.T) {
	n := parseNode(t, `{"Core":"sing","NodeID":46,
	                    "CertConfig":{"CertMode":"http","CertDomain":"a.example.com"}}`)
	if n.Options.CertConfig == nil || n.Options.CertConfig.CertDomain != "a.example.com" {
		t.Fatalf("CertConfig not read from the node top level: %+v", n.Options.CertConfig)
	}
}

// 🔴 On by default. It used to be opt-in, and the cost was a node behind the
// relay reporting every tunnelled user as 127.0.0.1 for weeks - device counting
// dead, online list useless, no output saying so. The install wizard also drops
// the setting whenever it regenerates config.json, so relying on someone to set
// it by hand is not a plan.
func TestProxyProtocolIsOnWhenTheConfigDoesNotMentionIt(t *testing.T) {
	n := parseNode(t, `{"Core":"sing","NodeID":46,"NodeType":"anytls"}`)
	if !n.Options.SingOptions.ProxyProtocol {
		t.Error("a config that says nothing got ProxyProtocol off; the tunnel would report 127.0.0.1")
	}
}

// A default is not a decision taken away from the operator: an explicit false
// must still turn it off, in either place the option can be written.
func TestProxyProtocolCanStillBeTurnedOff(t *testing.T) {
	flat := parseNode(t, `{"Core":"sing","NodeID":46,"ProxyProtocol":false}`)
	if flat.Options.SingOptions.ProxyProtocol {
		t.Error("an explicit top-level false was ignored")
	}
	nested := parseNode(t, `{"Core":"sing","NodeID":46,"SingOptions":{"ProxyProtocol":false}}`)
	if nested.Options.SingOptions.ProxyProtocol {
		t.Error("an explicit false in the nested block was ignored")
	}
}

// A nested block that says nothing about it must not silently reset the default
// - this is the shape every live config on the fleet actually has.
func TestANestedBlockWithoutTheKeyKeepsTheDefault(t *testing.T) {
	n := parseNode(t, `{"Core":"sing","NodeID":47,"NodeType":"anytls",
	                    "SingOptions":{"EnableTFO":false,"EnableSniff":true}}`)
	if !n.Options.SingOptions.ProxyProtocol {
		t.Error("a nested block that never mentions ProxyProtocol switched it off")
	}
}
