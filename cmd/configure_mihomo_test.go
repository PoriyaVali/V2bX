package cmd

import (
	"github.com/PoriyaVali/V2bX/api/panel"
	"testing"
)

func TestMihomoSetupCoreSelection(t *testing.T) {
	for _, protocol := range []string{"http", "socks5", "mieru", "shadowquic"} {
		info := &panel.NodeInfo{Type: protocol}
		if got := resolveSetupCore("auto", info); got != "mihomo" {
			t.Fatalf("%s selected %s", protocol, got)
		}
		if e := validateSetupCore("mihomo", info); e != nil {
			t.Fatal(e)
		}
	}
	if setupCoreSupports("mihomo", "wireguard") || setupCoreSupports("mihomo", "snell") {
		t.Fatal("client-only/single-key protocol advertised as managed server")
	}
}
