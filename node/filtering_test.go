package node

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

func vNode(typ string, security, port int, network, settings string) *panel.NodeInfo {
	v := &panel.VAllssNode{Network: network}
	if settings != "" {
		v.NetworkSettings = json.RawMessage(settings)
	}
	v.ServerPort = port
	return &panel.NodeInfo{Type: typ, Security: security, VAllss: v, Common: &v.CommonNode}
}

func ssNode(port int) *panel.NodeInfo {
	ss := &panel.ShadowsocksNode{Cipher: "2022-blake3-aes-128-gcm"}
	ss.ServerPort = port
	return &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
}

func TestFilteringAdvice(t *testing.T) {
	tlsCert := &conf.Options{CertConfig: &conf.CertConfig{CertMode: "http"}}
	selfCert := &conf.Options{CertConfig: &conf.CertConfig{CertMode: "self"}}
	hy2 := &panel.Hysteria2Node{}
	hy2.ServerPort = 443
	cases := []struct {
		name string
		node *panel.NodeInfo
		opts *conf.Options
		want []string // substrings of the advice expected, in order; none = no advice
	}{
		{"shadowsocks on 443", ssNode(443), nil, []string{"first packets"}},
		{"shadowsocks on 8443", ssNode(8443), nil, nil},
		{"plain vmess tcp on 80", vNode("vmess", panel.None, 80, "tcp", ""), nil, []string{"first packets"}},
		{"vmess tcp dressed as http on 80", vNode("vmess", panel.None, 80, "tcp", `{"header":{"type":"http"}}`), nil, nil},
		{"vless reality on 443", vNode("vless", panel.Reality, 443, "tcp", ""), nil, nil},
		{"vless tls on 443", vNode("vless", panel.Tls, 443, "tcp", ""), tlsCert, nil},
		{"plain ws on 80", vNode("vless", panel.None, 80, "ws", `{"path":"/"}`), nil, []string{"WebSocket"}},
		{"plain ws on 8080", vNode("vless", panel.None, 8080, "ws", `{"path":"/"}`), nil, nil},
		{"self-signed tls", vNode("vless", panel.Tls, 8443, "tcp", ""), selfCert, []string{"self-signed"}},
		{"hysteria2", &panel.NodeInfo{Type: "hysteria2", Security: panel.Tls, Hysteria2: hy2, Common: &hy2.CommonNode}, tlsCert, []string{"UDP"}},
	}
	for _, c := range cases {
		got := filteringAdviceFor(c.node, c.opts)
		if len(got) != len(c.want) {
			t.Errorf("%s: %d pieces of advice, want %d: %+v", c.name, len(got), len(c.want), got)
			continue
		}
		for i, w := range c.want {
			if !strings.Contains(got[i].msg, w) {
				t.Errorf("%s: advice %q does not mention %q", c.name, got[i].msg, w)
			}
		}
	}
	if filteringAdviceFor(nil, nil) != nil || filteringAdviceFor(&panel.NodeInfo{}, nil) != nil {
		t.Error("a node without panel data must produce no advice and no panic")
	}
}
