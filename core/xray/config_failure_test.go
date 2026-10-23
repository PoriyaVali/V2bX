package xray

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
)

func TestInvalidCoreConfigReturnsErrorAndPreservesEnvironment(t *testing.T) {
	t.Setenv("XRAY_LOCATION_ASSET", "/previous/assets")
	t.Setenv("XRAY_DNS_PATH", "/previous/dns.json")
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{broken`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"dns", "routing", "inbound", "outbound"} {
		for _, path := range []string{filepath.Join(dir, "missing.json"), invalid} {
			t.Run(kind+"/"+filepath.Base(path), func(t *testing.T) {
				c := conf.NewXrayConfig()
				c.AssetPath = dir
				switch kind {
				case "dns":
					c.DnsConfigPath = path
				case "routing":
					c.RouteConfigPath = path
				case "inbound":
					c.InboundConfigPath = path
				case "outbound":
					c.OutboundConfigPath = path
				}
				instance, err := New(&conf.CoreConfig{XrayConfig: c})
				if err == nil || instance != nil {
					t.Fatalf("bad config accepted: %v / %v", instance, err)
				}
				if os.Getenv("XRAY_LOCATION_ASSET") != "/previous/assets" || os.Getenv("XRAY_DNS_PATH") != "/previous/dns.json" {
					t.Fatal("failed replacement changed the running core's environment")
				}
			})
		}
	}
}

func TestNullCoreConfigReturnsError(t *testing.T) {
	for _, c := range []*conf.CoreConfig{nil, {}, {XrayConfig: &conf.XrayConfig{}}} {
		if instance, err := New(c); err == nil || instance != nil {
			t.Fatalf("null config accepted: %v / %v", instance, err)
		}
	}
}

func TestInvalidCoreBuildReturnsError(t *testing.T) {
	for _, tc := range []struct{ kind, body string }{
		{"dns", `{"servers":[{}]}`},
		{"routing", `{"rules":[{"type":"field","outboundTag":"direct","port":"invalid-port"}]}`},
		{"inbound", `[{"protocol":"unknown-protocol"}]`},
		{"outbound", `[{"protocol":"unknown-protocol"}]`},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			c := conf.NewXrayConfig()
			switch tc.kind {
			case "dns":
				c.DnsConfigPath = path
			case "routing":
				c.RouteConfigPath = path
			case "inbound":
				c.InboundConfigPath = path
			case "outbound":
				c.OutboundConfigPath = path
			}
			if instance, err := New(&conf.CoreConfig{XrayConfig: c}); err == nil || instance != nil {
				t.Fatalf("bad core build accepted: %v / %v", instance, err)
			}
		})
	}
}
