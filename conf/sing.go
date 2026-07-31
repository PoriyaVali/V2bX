package conf

import (
	"github.com/sagernet/sing-box/option"
)

type SingConfig struct {
	LogConfig        SingLogConfig `json:"Log"`
	NtpConfig        SingNtpConfig `json:"NTP"`
	OriginalPath     string        `json:"OriginalPath"`
	BlockedCountries []string      `json:"BlockedCountries"` // e.g. ["ir","cn"]
}

type SingLogConfig struct {
	Disabled  bool   `json:"Disable"`
	Level     string `json:"Level"`
	Output    string `json:"Output"`
	Timestamp bool   `json:"Timestamp"`
}

func NewSingConfig() *SingConfig {
	return &SingConfig{
		LogConfig: SingLogConfig{
			Level:     "error",
			Timestamp: true,
		},
		NtpConfig: SingNtpConfig{
			Enable:     false,
			Server:     "time.apple.com",
			ServerPort: 0,
		},
	}
}

type SingOptions struct {
	TCPFastOpen              bool                   `json:"EnableTFO"`
	SniffEnabled             bool                   `json:"EnableSniff"`
	SniffOverrideDestination bool                   `json:"SniffOverrideDestination"`
	EnableDNS                bool                   `json:"EnableDNS"`
	DomainStrategy           option.DomainStrategy  `json:"DomainStrategy"`
	FallBackConfigs          *FallBackConfigForSing `json:"FallBackConfigs"`
	Multiplex                *MultiplexConfig       `json:"MultiplexConfig"`
	// ProxyProtocol makes the inbound accept a HAProxy PROXY-protocol header so
	// the real client IP is recovered when the node sits behind the Hedioum
	// tunnel (which arrives from 127.0.0.1). It also accepts connections without
	// a header, so direct (non-tunnel) users keep working — safe to leave on.
	ProxyProtocol bool `json:"ProxyProtocol"`
	// DecoySite serves an ordinary-looking web page to anyone who completes the
	// TLS handshake but is not one of our users — an active prober, in other
	// words. Closing on them instead, which is what happens with this off, makes
	// the port answer like nothing else on the internet. Served in-process (see
	// core/sing/decoy.go), so there is nothing to install on the node.
	//
	// Defaults ON: NewSingOptions is the base every node config unmarshals over,
	// so existing nodes pick it up on upgrade without an edit. Set false to opt
	// out. Only anytls inbounds use it today — it is the only protocol here
	// whose library accepts a fallback handler.
	DecoySite *bool `json:"DecoySite"`
}

// DecoyEnabled reports whether the decoy should run. Pointer + nil check rather
// than a plain bool so an operator's explicit `"DecoySite": false` survives the
// default, which a zero-value bool could not express.
func (o *SingOptions) DecoyEnabled() bool {
	return o == nil || o.DecoySite == nil || *o.DecoySite
}

type SingNtpConfig struct {
	Enable     bool   `json:"Enable"`
	Server     string `json:"Server"`
	ServerPort uint16 `json:"ServerPort"`
}

type FallBackConfigForSing struct {
	// sing-box
	FallBack        FallBack            `json:"FallBack"`
	FallBackForALPN map[string]FallBack `json:"FallBackForALPN"`
}

type FallBack struct {
	Server     string `json:"Server"`
	ServerPort string `json:"ServerPort"`
}

type MultiplexConfig struct {
	Enabled bool          `json:"Enable"`
	Padding bool          `json:"Padding"`
	Brutal  BrutalOptions `json:"Brutal"`
}

type BrutalOptions struct {
	Enabled  bool `json:"Enable"`
	UpMbps   int  `json:"UpMbps"`
	DownMbps int  `json:"DownMbps"`
}

func NewSingOptions() *SingOptions {
	return &SingOptions{
		EnableDNS:                false,
		TCPFastOpen:              false,
		SniffEnabled:             true,
		SniffOverrideDestination: true,
		// On by default. It used to be opt-in, and the cost of that was a node
		// sitting behind the relay for weeks reporting every tunnelled user as
		// 127.0.0.1 - device counting dead, the online list useless, and not one
		// line of output to say so. The setting is also lost whenever the install
		// wizard regenerates config.json, so remembering to set it is not a plan.
		//
		// Safe for a node that has no tunnel: a header is only ever believed from
		// a loopback peer, so a direct connection is returned untouched - not
		// wrapped, not buffered, no deadline. The trust this widens is "a process
		// already running on this node could claim a false source address", which
		// only matters to someone who can already read config.json, the panel API
		// key, and every connection on the box.
		ProxyProtocol:   true,
		FallBackConfigs: &FallBackConfigForSing{},
		Multiplex:       &MultiplexConfig{},
	}
}
