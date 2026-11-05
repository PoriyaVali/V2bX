package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/xtls/xray-core/proxy/vless/inbound"
)

// A VLESS node with mlkem768x25519plus encryption as the panel stores it when
// the operator picks only the method: no mode, no ticket. The decryption
// string used to carry those as empty parts, xray rejected it, and the node
// never came up.
func TestBuildInbound_VlessEncryptionDefaults(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	for _, enc := range []panel.EncSettings{
		{PrivateKey: base64.RawURLEncoding.EncodeToString(key)},
		{Rtt: "0rtt", PrivateKey: base64.RawURLEncoding.EncodeToString(key)},
		{Rtt: "1rtt", Ticket: "0s", PrivateKey: base64.RawURLEncoding.EncodeToString(key)},
	} {
		v := &panel.VAllssNode{Network: "tcp", Encryption: "mlkem768x25519plus", EncryptionSettings: enc}
		v.ServerPort = 1234
		info := &panel.NodeInfo{Type: "vless", VAllss: v, Common: &v.CommonNode}
		in, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}, info, "t")
		if err != nil {
			t.Fatalf("%+v: %v", enc, err)
		}
		ps, err := in.ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		cfg := ps.(*inbound.Config)
		if cfg.Decryption == "" || strings.Contains(cfg.Decryption, "..") {
			t.Fatalf("%+v: decryption not configured: %q", enc, cfg.Decryption)
		}
		wantSeconds := int64(0)
		if enc.Rtt == "0rtt" {
			wantSeconds = 600
		}
		if cfg.SecondsFrom != wantSeconds {
			t.Fatalf("%+v: ticket lifetime %ds, want %ds", enc, cfg.SecondsFrom, wantSeconds)
		}
	}
}

// A VMess node over KCP with no network settings gets Xray's mKCP defaults,
// whether the panel leaves them out, sends null (as Irboard does) or [].
// null used to fall through to the transport switch, which has no KCP case,
// and the node never came up. KCP settings themselves are not translated.
func TestBuildInbound_KCPWithNoSettingsTakesXraysDefaults(t *testing.T) {
	for _, settings := range []string{"", "null", "[]"} {
		v := &panel.VAllssNode{Network: "kcp"}
		if settings != "" {
			v.NetworkSettings = json.RawMessage(settings)
		}
		v.ServerPort = 1234
		info := &panel.NodeInfo{Type: "vmess", VAllss: v, Common: &v.CommonNode}
		in, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}, info, "t")
		if err != nil {
			t.Fatalf("settings %q: %v", settings, err)
		}
		if got := in.ReceiverSettings.String(); !strings.Contains(got, "mkcp") {
			t.Fatalf("settings %q: the inbound is not mKCP: %s", settings, got)
		}
	}
	v := &panel.VAllssNode{Network: "kcp", NetworkSettings: json.RawMessage(`{"seed":"fictional"}`)}
	v.ServerPort = 1234
	if _, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}, &panel.NodeInfo{Type: "vmess", VAllss: v, Common: &v.CommonNode}, "t"); err == nil {
		t.Fatal("KCP settings were accepted, but they are not translated")
	}
}
