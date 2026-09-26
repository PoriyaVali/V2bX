package sing

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestApplyDNSDefaults(t *testing.T) {
	var o option.Options
	applyDNSDefaults(&o)
	if o.DNS == nil || o.DNS.CacheCapacity != defaultDNSCacheCapacity {
		t.Fatalf("no dns section: capacity %v", o.DNS)
	}
	o = option.Options{DNS: &option.DNSOptions{}}
	o.DNS.CacheCapacity = 2048
	applyDNSDefaults(&o)
	if o.DNS.CacheCapacity != 2048 {
		t.Fatal("an operator's own cache size was overridden")
	}
	o = option.Options{DNS: &option.DNSOptions{}}
	o.DNS.DisableCache = true
	applyDNSDefaults(&o)
	if o.DNS.CacheCapacity != 0 {
		t.Fatal("set a cache size on a node that disabled the cache")
	}
}
