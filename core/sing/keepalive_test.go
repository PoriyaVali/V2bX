package sing

import (
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/sagernet/sing-box/option"
)

func anytlsListen(t *testing.T, so *conf.SingOptions) option.ListenOptions {
	t.Helper()
	common := panel.CommonNode{ServerPort: 2087}
	info := &panel.NodeInfo{
		Type: "anytls", Security: panel.Tls,
		AnyTls: &panel.AnyTlsNode{CommonNode: common}, Common: &common,
	}
	in, err := getInboundOptions("t", info, &conf.Options{
		ListenIP:    "0.0.0.0",
		SingOptions: so,
		CertConfig:  &conf.CertConfig{CertMode: "none"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return in.Options.(*option.AnyTLSInboundOptions).ListenOptions
}

// Vanished devices must be reaped in minutes, not the ~16 minutes sing-box's
// own defaults take; UDP flows are dropped after 2 minutes of silence.
func TestInbound_DeadConnectionTimeouts(t *testing.T) {
	l := anytlsListen(t, conf.NewSingOptions())
	if got := time.Duration(l.TCPKeepAlive); got != 2*time.Minute {
		t.Errorf("keepalive idle = %s, want 2m", got)
	}
	if got := time.Duration(l.TCPKeepAliveInterval); got != 20*time.Second {
		t.Errorf("keepalive interval = %s, want 20s", got)
	}
	if got := time.Duration(l.UDPTimeout); got != 2*time.Minute {
		t.Errorf("udp timeout = %s, want 2m", got)
	}

	so := conf.NewSingOptions()
	so.TCPKeepAliveIdle, so.TCPKeepAliveInterval, so.UDPTimeout = 300, 75, 600
	l = anytlsListen(t, so)
	if time.Duration(l.TCPKeepAlive) != 5*time.Minute || time.Duration(l.TCPKeepAliveInterval) != 75*time.Second ||
		time.Duration(l.UDPTimeout) != 10*time.Minute {
		t.Errorf("config overrides ignored: %v %v %v", l.TCPKeepAlive, l.TCPKeepAliveInterval, l.UDPTimeout)
	}
}
