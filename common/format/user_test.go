package format

import "testing"

// The format is load-bearing: xray user emails, limiter keys and the sing
// device ledger are all built from it and matched against each other.
func TestUserTag(t *testing.T) {
	if got := UserTag("[https://p.example]-vless:3", "u-1"); got != "[https://p.example]-vless:3|u-1" {
		t.Fatalf("UserTag = %q", got)
	}
}
