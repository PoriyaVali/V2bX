package limiter

import (
	"sync"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
)

// An invalid pattern from the panel must be skipped, not panic: MustCompile
// took the whole process down, and again on every restart.
func TestUpdateRule_InvalidPatternIsSkipped(t *testing.T) {
	l := &Limiter{}
	err := l.UpdateRule(&panel.Rules{Regexp: []string{"(unclosed", "ads\\.example", ""}})
	if err != nil {
		t.Fatalf("UpdateRule failed the node over a bad rule: %v", err)
	}
	if !l.CheckDomainRule("ads.example") {
		t.Fatal("the valid rule next to the bad one was dropped")
	}
	if l.CheckDomainRule("") {
		t.Fatal("an empty rule matched everything")
	}
}

// `*.example.com` is how admins write "this domain and its subdomains".
func TestUpdateRule_WildcardDomain(t *testing.T) {
	l := &Limiter{}
	_ = l.UpdateRule(&panel.Rules{Regexp: []string{"*.example.com"}})
	for dest, want := range map[string]bool{
		"example.com":        true,
		"www.example.com":    true,
		"a.b.example.com":    true,
		"badexample.com":     false,
		"example.com.evil":   false,
		"notexample.com.org": false,
	} {
		if got := l.CheckDomainRule(dest); got != want {
			t.Errorf("CheckDomainRule(%q) = %v, want %v", dest, got, want)
		}
	}
}

func TestCheckRules_NoRulesInstalled(t *testing.T) {
	l := &Limiter{}
	if l.CheckDomainRule("x.com") || l.CheckProtocolRule("bittorrent") {
		t.Fatal("a limiter with no rules rejected something")
	}
}

// Rules are swapped while connections read them; run under -race.
func TestUpdateRule_ConcurrentWithChecks(t *testing.T) {
	l := &Limiter{}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = l.UpdateRule(&panel.Rules{Regexp: []string{"a\\.com"}, Protocol: []string{"bittorrent"}})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			l.CheckDomainRule("a.com")
			l.CheckProtocolRule("bittorrent")
		}
	}()
	wg.Wait()
}

func TestCheckDestinationRule(t *testing.T) {
	l := &Limiter{}
	_ = l.UpdateRule(&panel.Rules{
		Domain: []string{"domain:tracker.example", "full:exact.example", "keyword:casino", "geosite:no-such-list"},
		IP:     []string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "not-an-ip", "geoip:no-such-code"},
		Port:   []string{"25", "6881-6889", "70000", "9-1"},
	})
	cases := []struct {
		host string
		port uint16
		want string
	}{
		{"tracker.example", 443, "domain"},
		{"a.tracker.example", 443, "domain"},
		{"badtracker.example", 443, ""},
		{"exact.example", 443, "domain"},
		{"sub.exact.example", 443, ""},
		{"my-CASINO.example", 443, "domain"},
		{"10.1.2.3", 443, "ip"},
		{"192.0.2.7", 443, "ip"},
		{"192.0.2.8", 443, ""},
		{"2001:db8::1", 443, "ip"},
		{"[2001:db8::1]", 443, "ip"},
		// An address rule judges addresses, not names.
		{"ten.example", 443, ""},
		{"example.com", 25, "port"},
		{"example.com", 6885, "port"},
		{"example.com", 6890, ""},
	}
	for _, c := range cases {
		reject, kind := l.CheckDestinationRule(c.host, c.port)
		if kind != c.want || reject != (c.want != "") {
			t.Errorf("CheckDestinationRule(%q, %d) = %v %q, want %q", c.host, c.port, reject, kind, c.want)
		}
	}
}
