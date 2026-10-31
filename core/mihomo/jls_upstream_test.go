package mihomo

import (
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/stretchr/testify/assert"
)

// A ShadowQUIC node from the panel starts without a hand-written upstream:
// the site its clients name in their SNI answers probers.
func TestJLSUpstreamDefaultsToThePanelSNI(t *testing.T) {
	node := func(sni string, opt *conf.MihomoOptions) *node {
		return &node{info: &panel.NodeInfo{Mihomo: &panel.MihomoNode{CommonNode: panel.CommonNode{ServerName: sni}}}, options: &conf.Options{MihomoOptions: opt}}
	}
	upstream, err := node("www.example.com", nil).jlsUpstream()
	assert.NoError(t, err)
	assert.Equal(t, "www.example.com:443", upstream.Addr)
	assert.Equal(t, "www.example.com", upstream.SNI)

	configured := &conf.MihomoOptions{}
	configured.JLSUpstream.Addr, configured.JLSUpstream.SNI = "decoy.example.net:8443", "decoy.example.net"
	upstream, err = node("www.example.com", configured).jlsUpstream()
	assert.NoError(t, err)
	assert.Equal(t, "decoy.example.net:8443", upstream.Addr, "config.json wins")

	for _, sni := range []string{"", "203.0.113.7"} {
		_, err = node(sni, nil).jlsUpstream()
		assert.Error(t, err, "an IP or no SNI names no site: %q", sni)
	}
}
