package smartdns

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	cacheEntries = 32768
	maxTTL       = time.Hour
	maxNegative  = 5 * time.Minute
	// noSOA is how long an empty answer that names no SOA is kept.
	noSOA = 30 * time.Second
)

type cached struct {
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

// cache keeps answers for as long as their records allow.
type cache struct {
	mu sync.Mutex
	m  map[string]cached
}

func newCache() *cache { return &cache{m: map[string]cached{}} }

// cacheKey tells apart what may be answered differently: the question, and
// whether the client asked with EDNS, for DNSSEC records, or unchecked.
func cacheKey(req *dns.Msg) string {
	q := req.Question[0]
	var b strings.Builder
	b.WriteString(strings.ToLower(q.Name))
	b.WriteByte('|')
	b.WriteString(dns.Type(q.Qtype).String())
	b.WriteByte('|')
	b.WriteString(dns.Class(q.Qclass).String())
	if opt := req.IsEdns0(); opt != nil {
		b.WriteString("|e")
		if opt.Do() {
			b.WriteString("|do")
		}
	}
	if req.CheckingDisabled {
		b.WriteString("|cd")
	}
	return b.String()
}

// lifetime is how long msg may be answered from the cache; zero for not at
// all.
func lifetime(msg *dns.Msg) time.Duration {
	if msg.Truncated {
		return 0
	}
	empty := msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
	if empty {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl := soa.Hdr.Ttl
				if soa.Minttl < ttl {
					ttl = soa.Minttl
				}
				return min(time.Duration(ttl)*time.Second, maxNegative)
			}
		}
		return noSOA
	}
	if msg.Rcode != dns.RcodeSuccess {
		return 0
	}
	lowest := uint32(maxTTL / time.Second)
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			if ttl := rr.Header().Ttl; ttl < lowest {
				lowest = ttl
			}
		}
	}
	return time.Duration(lowest) * time.Second
}

func (c *cache) get(key string, now time.Time) *dns.Msg {
	c.mu.Lock()
	e, ok := c.m[key]
	if ok && !now.Before(e.expires) {
		delete(c.m, key)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return nil
	}
	msg := e.msg.Copy()
	age := uint32(now.Sub(e.stored) / time.Second)
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > age {
				h.Ttl -= age
			} else {
				h.Ttl = 0
			}
		}
	}
	return msg
}

func (c *cache) put(key string, msg *dns.Msg, now time.Time) {
	ttl := lifetime(msg)
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= cacheEntries {
		// Make room: what has expired, and otherwise whatever comes up.
		drop := cacheEntries / 8
		for k, e := range c.m {
			if drop == 0 {
				break
			}
			if !now.Before(e.expires) {
				delete(c.m, k)
				drop--
			}
		}
		for k := range c.m {
			if drop == 0 {
				break
			}
			delete(c.m, k)
			drop--
		}
	}
	c.m[key] = cached{msg: msg.Copy(), stored: now, expires: now.Add(ttl)}
}
