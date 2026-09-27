package xray

import (
	"crypto/rand"
	"encoding/base64"
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
