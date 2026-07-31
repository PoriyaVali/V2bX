package conf

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"encoding/json"

	"github.com/PoriyaVali/V2bX/common/json5"
)

type NodeConfig struct {
	ApiConfig ApiConfig `json:"-"`
	Options   Options   `json:"-"`
}

type rawNodeConfig struct {
	Include string          `json:"Include"`
	ApiRaw  json.RawMessage `json:"ApiConfig"`
	OptRaw  json.RawMessage `json:"Options"`
}

type ApiConfig struct {
	APIHost      string `json:"ApiHost"`
	APISendIP    string `json:"ApiSendIP"`
	NodeID       int    `json:"NodeID"`
	Key          string `json:"ApiKey"`
	NodeType     string `json:"NodeType"`
	Timeout      int    `json:"Timeout"`
	RuleListPath string `json:"RuleListPath"`
}

func (n *NodeConfig) UnmarshalJSON(data []byte) (err error) {
	rn := rawNodeConfig{}
	err = json.Unmarshal(data, &rn)
	if err != nil {
		return err
	}
	if len(rn.Include) != 0 {
		file, _ := strings.CutPrefix(rn.Include, ":")
		switch file {
		case "http", "https":
			rsp, err := http.Get(file)
			if err != nil {
				return err
			}
			defer rsp.Body.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(rsp.Body))
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
		default:
			f, err := os.Open(rn.Include)
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
			defer f.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(f))
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
		}
		err = json.Unmarshal(data, &rn)
		if err != nil {
			return fmt.Errorf("unmarshal include file error: %s", err)
		}
	}

	n.ApiConfig = ApiConfig{
		APIHost: "http://127.0.0.1",
		Timeout: 30,
	}
	if len(rn.ApiRaw) > 0 {
		err = json.Unmarshal(rn.ApiRaw, &n.ApiConfig)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.ApiConfig)
		if err != nil {
			return
		}
	}

	n.Options = Options{
		// Dual-stack by default: "::" accepts both IPv4 and IPv6 inbound
		// (Linux bindv6only=0). Empty SendIP leaves the outbound source
		// unbound so xray/freedom can reach IPv6 destinations too.
		ListenIP:   "::",
		SendIP:     "",
		CertConfig: NewCertConfig(),
	}
	if len(rn.OptRaw) > 0 {
		err = json.Unmarshal(rn.OptRaw, &n.Options)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.Options)
		if err != nil {
			return
		}
	}
	return
}

type Options struct {
	Name                   string          `json:"Name"`
	Core                   string          `json:"Core"`
	CoreName               string          `json:"CoreName"`
	ListenIP               string          `json:"ListenIP"`
	SendIP                 string          `json:"SendIP"`
	DeviceOnlineMinTraffic int64           `json:"DeviceOnlineMinTraffic"`
	ReportMinTraffic       int64           `json:"ReportMinTraffic"`
	LimitConfig            LimitConfig     `json:"LimitConfig"`
	RawOptions             json.RawMessage `json:"RawOptions"`
	XrayOptions            *XrayOptions    `json:"XrayOptions"`
	SingOptions            *SingOptions    `json:"SingOptions"`
	Hysteria2ConfigPath    string          `json:"Hysteria2ConfigPath"`
	CertConfig             *CertConfig     `json:"CertConfig"`
}

// overlayCoreOptions applies a nested `"<key>": { … }` block on top of options
// already read from the node's top level.
//
// The core options are unmarshalled from the WHOLE node object, so they have
// always been read from the node's TOP level - while the setup wizard writes
// them as a nested block, and a nested block is the shape most people assume
// from the field name. Those values were silently discarded: parsed once by the
// generic pass over Options, then thrown away when the core branch reassigns the
// pointer and re-parses. Nothing errored, so the config looked applied and was
// not.
//
// It went unnoticed because the wizard's block repeats the defaults exactly
// (EnableTFO false, EnableSniff true, SniffOverrideDestination true, EnableDNS
// false), so the only thing an operator could actually lose was MultiplexConfig
// - and one full day was spent chasing a tunnel that would not carry TLS,
// because ProxyProtocol had been written there by hand and never took effect.
//
// Both shapes are now honoured, nested last so the more specific wins. Absent or
// malformed nested blocks leave the top-level values untouched.
func overlayCoreOptions(data []byte, key string, target any) error {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil // not an object we can inspect; top-level values stand
	}
	nested, ok := wrapper[key]
	if !ok || len(nested) == 0 || string(nested) == "null" {
		return nil
	}
	return json.Unmarshal(nested, target)
}

func (o *Options) UnmarshalJSON(data []byte) error {
	type opt Options
	err := json.Unmarshal(data, (*opt)(o))
	if err != nil {
		return err
	}
	switch o.Core {
	case "xray":
		o.XrayOptions = NewXrayOptions()
		if err = json.Unmarshal(data, o.XrayOptions); err != nil {
			return err
		}
		return overlayCoreOptions(data, "XrayOptions", o.XrayOptions)
	case "sing":
		o.SingOptions = NewSingOptions()
		if err = json.Unmarshal(data, o.SingOptions); err != nil {
			return err
		}
		return overlayCoreOptions(data, "SingOptions", o.SingOptions)
	case "hysteria2":
		o.RawOptions = data
		return nil
	default:
		o.Core = ""
		o.RawOptions = data
	}
	return nil
}
