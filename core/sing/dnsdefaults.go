package sing

import (
	"context"
	"fmt"

	"github.com/PoriyaVali/V2bX/common/smartdns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// forwarderTag names the DNS server that is V2bX's own forwarder.
const forwarderTag = "v2bx-dns"

// defaultDNSCacheCapacity replaces sing-box's 1024-entry DNS cache when the
// node's config does not choose a size.
//
// Every inbound here overrides the destination with the sniffed domain, so
// the node resolves each destination itself. With a few hundred subscribers
// browsing, 1024 names turn over in minutes and the same popular hosts are
// looked up again and again - each miss is a round trip added to someone's
// connection. 16384 entries cost a few megabytes.
const defaultDNSCacheCapacity = 16384

func applyDNSDefaults(ctx context.Context, options *option.Options) error {
	if options.DNS == nil {
		options.DNS = &option.DNSOptions{}
	}
	// Where the config names no DNS server, or the machine's own ("local",
	// as the installed sing_origin.json does), sing-box asks the machine's
	// resolvers itself, over UDP. V2bX's forwarder asks the same ones, and
	// over TCP while their UDP answers are being lost. A server of the
	// operator's choosing is kept.
	if fwd := smartdns.Active(); fwd != nil {
		through := func(tag string) (option.DNSServerOptions, error) {
			raw := fmt.Sprintf(`{"type":"udp","tag":%q,"server":%q,"server_port":%d}`,
				tag, fwd.Addr().Addr().String(), fwd.Addr().Port())
			server, err := json.UnmarshalExtendedContext[option.DNSServerOptions](ctx, []byte(raw))
			if err != nil {
				return server, fmt.Errorf("point DNS at the forwarder: %w", err)
			}
			return server, nil
		}
		if len(options.DNS.Servers) == 0 {
			server, err := through(forwarderTag)
			if err != nil {
				return err
			}
			options.DNS.Servers, options.DNS.Final = []option.DNSServerOptions{server}, forwarderTag
		}
		for i, existing := range options.DNS.Servers {
			if existing.Type != C.DNSTypeLocal {
				continue
			}
			server, err := through(existing.Tag)
			if err != nil {
				return err
			}
			options.DNS.Servers[i] = server
		}
	}
	if options.DNS.CacheCapacity == 0 && !options.DNS.DisableCache {
		options.DNS.CacheCapacity = defaultDNSCacheCapacity
	}
	return nil
}
