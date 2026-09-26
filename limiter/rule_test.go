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
