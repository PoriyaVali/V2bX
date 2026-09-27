//go:build linux

package cmd

import (
	"strings"
	"testing"
)

// The file is read by sysctl: every setting once, as key=value, and nothing
// else but comments.
func TestRenderSysctlConf(t *testing.T) {
	got := map[string]string{}
	for _, line := range strings.Split(renderSysctlConf(networkTuning), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("not key=value: %q", line)
		}
		if _, dup := got[k]; dup {
			t.Fatalf("%s set twice", k)
		}
		got[k] = v
	}
	if len(got) != len(networkTuning) {
		t.Fatalf("file sets %d keys, want %d", len(got), len(networkTuning))
	}
	for _, s := range networkTuning {
		if got[s.key] != s.value {
			t.Errorf("%s = %q, want %q", s.key, got[s.key], s.value)
		}
		if strings.Contains(s.why, "\n") {
			t.Errorf("%s: explanation spans lines and would break the file", s.key)
		}
	}
}
