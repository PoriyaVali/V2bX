package sing

import "github.com/sagernet/sing-box/option"

// defaultDNSCacheCapacity replaces sing-box's 1024-entry DNS cache when the
// node's config does not choose a size.
//
// Every inbound here overrides the destination with the sniffed domain, so
// the node resolves each destination itself. With a few hundred subscribers
// browsing, 1024 names turn over in minutes and the same popular hosts are
// looked up again and again - each miss is a round trip added to someone's
// connection. 16384 entries cost a few megabytes.
const defaultDNSCacheCapacity = 16384

func applyDNSDefaults(options *option.Options) {
	if options.DNS == nil {
		options.DNS = &option.DNSOptions{}
	}
	if options.DNS.CacheCapacity == 0 && !options.DNS.DisableCache {
		options.DNS.CacheCapacity = defaultDNSCacheCapacity
	}
}
