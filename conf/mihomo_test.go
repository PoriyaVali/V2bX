package conf

import (
	"encoding/json"
	"testing"
)

func TestMihomoCoreAndNestedNodeOptions(t *testing.T) {
	var core CoreConfig
	if e := json.Unmarshal([]byte(`{"Type":"mihomo","DialTimeout":8,"AllowPrivateDestinations":true}`), &core); e != nil {
		t.Fatal(e)
	}
	if core.MihomoConfig == nil || core.MihomoConfig.DialTimeout != 8 || core.MihomoConfig.UDPTimeout != 120 || !core.MihomoConfig.AllowPrivateDestinations {
		t.Fatal(core.MihomoConfig)
	}
	var node Options
	if e := json.Unmarshal([]byte(`{"Core":"mihomo","MihomoOptions":{"JLSUpstream":{"Addr":"decoy.example.test:443","SNI":"decoy.example.test"}}}`), &node); e != nil {
		t.Fatal(e)
	}
	if node.MihomoOptions == nil || node.MihomoOptions.JLSUpstream.Addr != "decoy.example.test:443" {
		t.Fatal(node.MihomoOptions)
	}
}
