package sing

import (
	"context"
	"testing"

	"github.com/PoriyaVali/V2bX/common/smartdns"
	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestApplyDNSDefaults(t *testing.T) {
	var o option.Options
	_ = applyDNSDefaults(context.Background(), &o)
	if o.DNS == nil || o.DNS.CacheCapacity != defaultDNSCacheCapacity {
		t.Fatalf("no dns section: capacity %v", o.DNS)
	}
	o = option.Options{DNS: &option.DNSOptions{}}
	o.DNS.CacheCapacity = 2048
	_ = applyDNSDefaults(context.Background(), &o)
	if o.DNS.CacheCapacity != 2048 {
		t.Fatal("an operator's own cache size was overridden")
	}
	o = option.Options{DNS: &option.DNSOptions{}}
	o.DNS.DisableCache = true
	_ = applyDNSDefaults(context.Background(), &o)
	if o.DNS.CacheCapacity != 0 {
		t.Fatal("set a cache size on a node that disabled the cache")
	}
}

// With V2bX's forwarder running, a node whose config names no DNS server
// resolves through it; one that names its own keeps them.
func TestApplyDNSDefaultsPointsAtTheForwarder(t *testing.T) {
	if _, err := smartdns.Enable(smartdns.Config{Servers: []string{"192.0.2.53"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(smartdns.Disable)
	ctx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
	var o option.Options
	if err := applyDNSDefaults(ctx, &o); err != nil {
		t.Fatal(err)
	}
	if len(o.DNS.Servers) != 1 || o.DNS.Servers[0].Tag != forwarderTag || o.DNS.Final != forwarderTag {
		t.Fatalf("servers %+v final %q", o.DNS.Servers, o.DNS.Final)
	}
	// The installed sing_origin.json names the machine's resolver, in the
	// legacy form: it is the forwarder under the same tag. A server of the
	// operator's choosing stays.
	installed, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(
		`{"dns":{"servers":[{"tag":"local","address":"local"},{"tag":"mine","type":"tcp","server":"198.51.100.9"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyDNSDefaults(ctx, &installed); err != nil {
		t.Fatal(err)
	}
	servers := installed.DNS.Servers
	if len(servers) != 2 || servers[0].Tag != "local" || servers[0].Type != C.DNSTypeUDP || servers[1].Tag != "mine" || servers[1].Type != C.DNSTypeTCP {
		t.Fatalf("servers %+v", servers)
	}
	udp, ok := servers[0].Options.(*option.RemoteDNSServerOptions)
	if !ok || udp.Server != "127.0.0.1" || udp.ServerPort != smartdns.Active().Addr().Port() {
		t.Fatalf("the local server is not the forwarder: %+v", servers[0].Options)
	}
}
