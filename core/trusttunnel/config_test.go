package trusttunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of the vpn.toml the setup wizard writes: comments, top-level
// keys, then tables.
const wizardVpnToml = `# The address to listen on
listen_address = "0.0.0.0:443"

# Whether IPv6 connections can be routed
ipv6_available = true

allow_private_network_connections = false

[listen_protocols]

[listen_protocols.quic]
ipv6_available = "a nested key of the same name must be left alone"
`

func TestSetTopLevel_Ipv6Available(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpn.toml")
	if err := os.WriteFile(path, []byte(wizardVpnToml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setTopLevel(path, "ipv6_available", "false"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	s := string(got)
	if !strings.Contains(s, "\nipv6_available = false\n") || strings.Contains(s, "ipv6_available = true") {
		t.Fatalf("top-level ipv6_available not set:\n%s", s)
	}
	if !strings.Contains(s, `ipv6_available = "a nested key`) {
		t.Fatalf("a key inside a table was changed:\n%s", s)
	}
	if strings.Count(s, "\n") != strings.Count(wizardVpnToml, "\n") {
		t.Fatalf("lines added or lost:\n%s", s)
	}
}

func TestSetTopLevel_AddsMissingKeyBeforeTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpn.toml")
	in := "listen_address = \"0.0.0.0:443\"\n\n[listen_protocols]\n"
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setTopLevel(path, "ipv6_available", "false"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	s := string(got)
	key, table := strings.Index(s, "ipv6_available = false"), strings.Index(s, "[listen_protocols]")
	if key < 0 || key > table {
		t.Fatalf("key not added before the first table:\n%s", s)
	}
}
