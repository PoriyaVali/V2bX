package limiter

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/PoriyaVali/V2bX/api/panel"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/geodata"
)

// ruleSet is replaced as a whole, never edited in place: connections read it
// on every dial while a reload may be installing the next one.
type ruleSet struct {
	domains   []*regexp.Regexp
	matchers  []geodata.DomainMatcher // "domain:", "full:", "geosite:"...
	ips       []geodata.IPMatcher     // block_ip
	ports     []portRange             // block_port
	protocols []string
}

type portRange struct{ from, to uint16 }

func (l *Limiter) currentRules() *ruleSet {
	if r := l.rules.Load(); r != nil {
		return r
	}
	return &ruleSet{}
}

func (l *Limiter) CheckDomainRule(destination string) (reject bool) {
	rules := l.currentRules()
	for _, re := range rules.domains {
		if re.MatchString(destination) {
			return true
		}
	}
	if len(rules.matchers) > 0 && destination != "" {
		d := strings.ToLower(destination)
		for _, m := range rules.matchers {
			if m.MatchAny(d) {
				return true
			}
		}
	}
	return false
}

func (l *Limiter) CheckProtocolRule(protocol string) (reject bool) {
	for _, p := range l.currentRules().protocols {
		if p == protocol {
			return true
		}
	}
	return false
}

// CheckDestinationRule reports whether the node's rules refuse a connection to
// host (a domain or an address) on port, and which kind of rule did: "domain",
// "ip" or "port". An address rule matches only a destination that is an
// address; a connection by domain name is judged by the domain rules.
func (l *Limiter) CheckDestinationRule(host string, port uint16) (reject bool, kind string) {
	if l.CheckDomainRule(host) {
		return true, "domain"
	}
	rules := l.currentRules()
	if len(rules.ips) > 0 {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			for _, m := range rules.ips {
				if m.Match(ip) {
					return true, "ip"
				}
			}
		}
	}
	for _, r := range rules.ports {
		if port >= r.from && port <= r.to {
			return true, "port"
		}
	}
	return false, ""
}

// compileDomainRule turns one panel "block" entry into a matcher.
//
// The entries are admin-typed. `*.example.com` is how most people write "this
// domain and everything under it", and as a regular expression it is invalid
// (nothing before the `*`) - which regexp.MustCompile answered with a panic,
// taking down the process and every node it served, then again on each
// restart because the panel still sent the same rule. Read that one form the
// way it was meant, and skip anything else that does not compile.
func compileDomainRule(pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err == nil {
		return re, nil
	}
	if strings.HasPrefix(pattern, "*.") {
		return regexp.Compile(`(^|\.)` + regexp.QuoteMeta(strings.TrimPrefix(pattern, "*.")) + `$`)
	}
	return nil, err
}

// compilePrefixedDomainRule builds a matcher for a rule in xray's syntax
// ("domain:", "full:", "keyword:", "geosite:"...). geosite rules read
// geosite.dat from the asset directory.
func compilePrefixedDomainRule(rule string) (geodata.DomainMatcher, error) {
	r, err := geodata.ParseDomainRule(rule, geodata.Domain_Substr)
	if err != nil {
		return nil, err
	}
	return geodata.DomainReg.BuildDomainMatcher([]*geodata.DomainRule{r})
}

// compileIPRule builds a matcher for an address, a CIDR or "geoip:<code>"
// (read from geoip.dat in the asset directory).
func compileIPRule(rule string) (geodata.IPMatcher, error) {
	rs, err := geodata.ParseIPRules([]string{rule})
	if err != nil {
		return nil, err
	}
	return geodata.IPReg.BuildIPMatcher(rs)
}

// parsePortRule reads "443" or "1000-2000".
func parsePortRule(rule string) (portRange, error) {
	from, to, isRange := strings.Cut(rule, "-")
	a, err := strconv.ParseUint(strings.TrimSpace(from), 10, 16)
	if err != nil {
		return portRange{}, fmt.Errorf("not a port: %q", rule)
	}
	b := a
	if isRange {
		if b, err = strconv.ParseUint(strings.TrimSpace(to), 10, 16); err != nil || b < a {
			return portRange{}, fmt.Errorf("not a port range: %q", rule)
		}
	}
	return portRange{uint16(a), uint16(b)}, nil
}

// UpdateRule installs the node's audit rules. It never fails the node: a rule
// that cannot be used is logged and left out, since refusing to run a node
// over one bad audit entry would cut off every user on it.
func (l *Limiter) UpdateRule(rule *panel.Rules) error {
	next := &ruleSet{protocols: append([]string(nil), rule.Protocol...)}
	skip := func(kind, pattern string, err error) {
		log.WithField("rule", pattern).Warnf("Skipping a %s rule that cannot be used: %s", kind, err)
	}
	for _, pattern := range rule.Regexp {
		if strings.TrimSpace(pattern) == "" {
			continue
		}
		re, err := compileDomainRule(pattern)
		if err != nil {
			skip("domain", pattern, err)
			continue
		}
		next.domains = append(next.domains, re)
	}
	for _, pattern := range rule.Domain {
		m, err := compilePrefixedDomainRule(strings.TrimSpace(pattern))
		if err != nil {
			skip("domain", pattern, err)
			continue
		}
		next.matchers = append(next.matchers, m)
	}
	for _, pattern := range rule.IP {
		m, err := compileIPRule(strings.TrimSpace(pattern))
		if err != nil {
			skip("block_ip", pattern, err)
			continue
		}
		next.ips = append(next.ips, m)
	}
	for _, pattern := range rule.Port {
		r, err := parsePortRule(pattern)
		if err != nil {
			skip("block_port", pattern, err)
			continue
		}
		next.ports = append(next.ports, r)
	}
	l.rules.Store(next)
	return nil
}
