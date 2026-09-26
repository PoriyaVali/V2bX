package limiter

import (
	"regexp"
	"strings"

	"github.com/PoriyaVali/V2bX/api/panel"
	log "github.com/sirupsen/logrus"
)

// ruleSet is replaced as a whole, never edited in place: connections read it
// on every dial while a reload may be installing the next one.
type ruleSet struct {
	domains   []*regexp.Regexp
	protocols []string
}

func (l *Limiter) currentRules() *ruleSet {
	if r := l.rules.Load(); r != nil {
		return r
	}
	return &ruleSet{}
}

func (l *Limiter) CheckDomainRule(destination string) (reject bool) {
	for _, re := range l.currentRules().domains {
		if re.MatchString(destination) {
			return true
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

// UpdateRule installs the node's audit rules. It never fails the node: a rule
// that cannot be used is logged and left out, since refusing to run a node
// over one bad audit entry would cut off every user on it.
func (l *Limiter) UpdateRule(rule *panel.Rules) error {
	next := &ruleSet{protocols: append([]string(nil), rule.Protocol...)}
	for _, pattern := range rule.Regexp {
		if strings.TrimSpace(pattern) == "" {
			continue
		}
		re, err := compileDomainRule(pattern)
		if err != nil {
			log.WithField("rule", pattern).Warn("Skipping an audit rule that is not a valid pattern: ", err)
			continue
		}
		next.domains = append(next.domains, re)
	}
	l.rules.Store(next)
	return nil
}
