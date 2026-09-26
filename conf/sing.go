package conf

import (
	"time"

	"github.com/sagernet/sing-box/option"
)

type SingConfig struct {
	LogConfig        SingLogConfig `json:"Log"`
	NtpConfig        SingNtpConfig `json:"NTP"`
	OriginalPath     string        `json:"OriginalPath"`
	BlockedCountries []string      `json:"BlockedCountries"` // e.g. ["ir","cn"]
	// AllowPrivateDestinations lets users reach loopback, private and
	// link-local addresses through the node. Off by default: those are the
	// node's own services and its hosting provider's internal network.
	AllowPrivateDestinations bool `json:"AllowPrivateDestinations"`
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
	// Seconds; 0 = the defaults below.
	TCPKeepAliveIdle     int `json:"TCPKeepAliveIdle"`
	TCPKeepAliveInterval int `json:"TCPKeepAliveInterval"`
	UDPTimeout           int `json:"UDPTimeout"`
	// Congestion control for subscribers' connections; "" = bbr, "none" =
	// the system default. See TCPCongestionName.
	TCPCongestion string `json:"TCPCongestion"`
}

// DecoyEnabled reports whether the decoy should run. Pointer + nil check rather
// than a plain bool so an operator's explicit `"DecoySite": false` survives the
// default, which a zero-value bool could not express.
// How long a subscriber's vanished device may keep holding a connection.
//
// A phone that loses signal or switches network sends no FIN, so its session
// stays open on the node - with every stream and outbound connection in it -
// until TCP keepalive declares it dead. sing-box's defaults (5 min idle, then
// probes 75 s apart, 9 of them) take about 16 minutes; on Iranian mobile
// networks that is a lot of dead sessions carried at any moment. These make it
// about 5 minutes. A live device answers a probe from its kernel without
// waking any app, and is probed at most once per idle period.
const (
	DefaultTCPKeepAliveIdle     = 120 // seconds of silence before the first probe
	DefaultTCPKeepAliveInterval = 20  // seconds between unanswered probes
	// A UDP flow (QUIC, DNS, calls) is kept this long after its last packet.
	// sing-box keeps 5 minutes; QUIC gives up after 30 s of silence anyway.
	DefaultUDPTimeout = 120
)

func secondsOr(v, def int) time.Duration {
	if v <= 0 {
		v = def
	}
	return time.Duration(v) * time.Second
}

// KeepAliveIdle, KeepAliveInterval and UDPIdle resolve the timeouts, applying
// the defaults above to unset fields.
func (o *SingOptions) KeepAliveIdle() time.Duration {
	return secondsOr(o.TCPKeepAliveIdle, DefaultTCPKeepAliveIdle)
}

func (o *SingOptions) KeepAliveInterval() time.Duration {
	return secondsOr(o.TCPKeepAliveInterval, DefaultTCPKeepAliveInterval)
}

func (o *SingOptions) UDPIdle() time.Duration {
	return secondsOr(o.UDPTimeout, DefaultUDPTimeout)
}

// TCPCongestionName is the congestion control subscribers' connections use.
//
// BBR by default, for these connections only - the system default stays as it
// is. Most nodes run the kernel default, CUBIC, which reads every lost packet
// as congestion and halves its rate; on Iranian mobile paths, where loss comes
// from the radio and from throttling rather than full queues, that keeps the
// link far below what it can carry and piles data into queues, which is what
// users feel as lag. BBR paces by measured bandwidth and round-trip time
// instead. A kernel without it keeps its default. "none" opts out.
func (o *SingOptions) TCPCongestionName() string {
	switch o.TCPCongestion {
	case "":
		return "bbr"
	case "none", "default", "system":
		return ""
	}
	return o.TCPCongestion
}

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
