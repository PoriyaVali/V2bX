package hy2

import "testing"

func TestQUICInitialStreamWindowIsApplied(t *testing.T) {
	n := &Hysteria2node{}
	for _, window := range []uint64{16384, 1024 * 1024, 16 * 1024 * 1024} {
		c := &serverConfig{}
		c.QUIC.InitStreamReceiveWindow = window
		c.QUIC.InitConnectionReceiveWindow = 32 * 1024 * 1024
		got, err := n.getQUICConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		if got.InitialStreamReceiveWindow != window {
			t.Errorf("configured initial stream window %d became %d", window, got.InitialStreamReceiveWindow)
		}
		if got.InitialConnectionReceiveWindow != c.QUIC.InitConnectionReceiveWindow {
			t.Errorf("stream window changed the connection window: %d", got.InitialConnectionReceiveWindow)
		}
	}
}

func TestQUICPathMTUDiscoverySettingIsApplied(t *testing.T) {
	n := &Hysteria2node{}
	for _, disabled := range []bool{true, false} {
		c := &serverConfig{}
		c.QUIC.DisablePathMTUDiscovery = disabled
		got, err := n.getQUICConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		if got.DisablePathMTUDiscovery != disabled {
			t.Errorf("disablePathMTUDiscovery=%v became %v", disabled, got.DisablePathMTUDiscovery)
		}
	}
}
