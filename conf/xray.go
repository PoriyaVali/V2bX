package conf

type XrayConfig struct {
	LogConfig          *XrayLogConfig        `json:"Log"`
	AssetPath          string                `json:"AssetPath"`
	DnsConfigPath      string                `json:"DnsConfigPath"`
	RouteConfigPath    string                `json:"RouteConfigPath"`
	ConnectionConfig   *XrayConnectionConfig `json:"XrayConnectionConfig"`
	InboundConfigPath  string                `json:"InboundConfigPath"`
	OutboundConfigPath string                `json:"OutboundConfigPath"`
}

type XrayLogConfig struct {
	Level string `json:"Level"`
	// AccessPath is where xray logs each connection: a file path, "console"
	// for the service log, or empty for no access log (the default).
	AccessPath string `json:"AccessPath"`
	ErrorPath  string `json:"ErrorPath"`
}

type XrayConnectionConfig struct {
	Handshake    uint32 `json:"handshake"`
	ConnIdle     uint32 `json:"connIdle"`
	UplinkOnly   uint32 `json:"uplinkOnly"`
	DownlinkOnly uint32 `json:"downlinkOnly"`
	BufferSize   int32  `json:"bufferSize"`
}

func NewXrayConfig() *XrayConfig {
	return &XrayConfig{
		LogConfig: &XrayLogConfig{
			Level:      "warning",
			AccessPath: "",
			ErrorPath:  "",
		},
		AssetPath:          "/etc/V2bX/",
		DnsConfigPath:      "",
		InboundConfigPath:  "",
		OutboundConfigPath: "",
		RouteConfigPath:    "",
		ConnectionConfig: &XrayConnectionConfig{
			// Seconds a new connection has to finish its handshake: on a plain
			// TLS node the whole TLS handshake plus the first request. xray's own
			// 4 assumes a clean path. On a lossy mobile path with a one-second
			// round trip, that is 1.5 round trips plus two retransmission
			// timeouts (1 s, then 2 s), and those connections were killed
			// moments before they would have succeeded - the user sees "timeout"
			// and retries into the same conditions. sing nodes allow TLS
			// handshakes 60 s. A probe that never completes is still let go
			// after a few seconds, which costs one idle socket.
			Handshake: 10,
			// Seconds a connection may carry nothing before xray closes it.
			// 300 is xray's own default. It was 30, which closed a browser's
			// keep-alive connections, and apps' idle push connections, while
			// they still meant to reuse them: the next request paid a new
			// handshake to the node - one to three round trips from the user,
			// a few hundred milliseconds on a mobile link - and chat apps
			// showed "connecting" between messages. A vanished device is still
			// let go: nothing comes from it, so it reaches this same limit -
			// after five minutes, as sing's keepalive settings do.
			ConnIdle:     300,
			UplinkOnly:   2,
			DownlinkOnly: 4,
			BufferSize:   64,
		},
	}
}

type XrayOptions struct {
	EnableProxyProtocol bool                    `json:"EnableProxyProtocol"`
	EnableDNS           bool                    `json:"EnableDNS"`
	DNSType             string                  `json:"DNSType"`
	EnableUot           bool                    `json:"EnableUot"`
	EnableTFO           bool                    `json:"EnableTFO"`
	DisableIVCheck      bool                    `json:"DisableIVCheck"`
	DisableSniffing     bool                    `json:"DisableSniffing"`
	EnableFallback      bool                    `json:"EnableFallback"`
	FallBackConfigs     []FallBackConfigForXray `json:"FallBackConfigs"`
	// TCPCongestion is the congestion control for subscribers' connections:
	// "" = bbr, "none" = the system default. The same setting sing nodes have.
	TCPCongestion string `json:"TCPCongestion"`
	// TCPNotSentLowat caps the bytes queued unsent on a subscriber's
	// connection: 0 = DefaultTCPNotSentLowat, negative = the system default.
	TCPNotSentLowat int `json:"TCPNotSentLowat"`
	// TCP keepalive on subscribers' connections, in seconds: 0 = the defaults
	// sing nodes use (DefaultTCPKeepAliveIdle / DefaultTCPKeepAliveInterval),
	// negative = no keepalive.
	TCPKeepAliveIdle     int `json:"TCPKeepAliveIdle"`
	TCPKeepAliveInterval int `json:"TCPKeepAliveInterval"`
	// DecoySite answers a stranger who completes the TLS handshake of a VLESS
	// or Trojan node over TCP with an ordinary web page (common/decoy) instead
	// of a closed socket, when EnableFallback is off. Defaults ON, as on sing
	// nodes; set false to opt out.
	DecoySite *bool `json:"DecoySite"`
	// REALITY relays every connection it cannot authenticate to the borrowed
	// site. Past RealityFallbackAfterKB kilobytes in either direction, such a
	// connection is held to RealityFallbackKBps. 0 = the defaults below,
	// negative = no limit.
	RealityFallbackAfterKB int `json:"RealityFallbackAfterKB"`
	RealityFallbackKBps    int `json:"RealityFallbackKBps"`
}

// REALITY fallback limits: a prober or crawler loading the borrowed site's
// pages is well inside 4 MiB per connection and never notices; someone
// running bulk traffic through the node's address - REALITY nodes in Iran are
// found and used as free relays to Cloudflare-fronted tunnels
// (net4people/bbs#359) - is held to 64 KiB/s. Iranian operators block an
// address in proportion to the traffic they see on it, so a stranger's volume
// costs every user of the node.
const (
	DefaultRealityFallbackAfterKB = 4096
	DefaultRealityFallbackKBps    = 64
)

// RealityFallbackLimit resolves the REALITY fallback limits in bytes: the
// allowance before limiting starts and the rate after it. A zero rate means
// no limit.
func (o *XrayOptions) RealityFallbackLimit() (afterBytes, bytesPerSec uint64) {
	if o.RealityFallbackAfterKB < 0 || o.RealityFallbackKBps < 0 {
		return 0, 0
	}
	after, rate := o.RealityFallbackAfterKB, o.RealityFallbackKBps
	if after == 0 {
		after = DefaultRealityFallbackAfterKB
	}
	if rate == 0 {
		rate = DefaultRealityFallbackKBps
	}
	return uint64(after) * 1024, uint64(rate) * 1024
}

// DecoyEnabled reports whether the decoy should run: unless set to false.
func (o *XrayOptions) DecoyEnabled() bool {
	return o == nil || o.DecoySite == nil || *o.DecoySite
}

// KeepAlive resolves TCPKeepAliveIdle and TCPKeepAliveInterval for xray's
// socket options, in seconds.
//
// xray listens with keepalive OFF unless told otherwise, so a phone that lost
// signal or changed network kept its connection on an xray node until the
// five-minute idle policy noticed, and a connection that was merely quiet got
// nothing that refreshed the mobile carrier's NAT entry for it. These are the
// sing nodes' values. -1 is xray's "off"; it must be set on both, because xray
// refuses to listen when only one of the two is negative.
func (o *XrayOptions) KeepAlive() (idle, interval int32) {
	if o.TCPKeepAliveIdle < 0 || o.TCPKeepAliveInterval < 0 {
		return -1, -1
	}
	return int32(secondsOr(o.TCPKeepAliveIdle, DefaultTCPKeepAliveIdle).Seconds()),
		int32(secondsOr(o.TCPKeepAliveInterval, DefaultTCPKeepAliveInterval).Seconds())
}

// DefaultTCPNotSentLowat keeps at most 16 KiB queued unsent per subscriber
// connection, so a small reply is not queued behind megabytes of a download
// sharing the connection - an HTTP/2 page, a multiplexed session. Measured on
// an accepted connection drained at 2 MiB/s: such a reply waited a median
// 1.44 s without it and 47 ms with it, and bulk throughput was unchanged.
const DefaultTCPNotSentLowat = 16384

// TCPCongestionName resolves TCPCongestion: "bbr" unless the node chose
// another algorithm, or "" for the system default.
func (o *XrayOptions) TCPCongestionName() string {
	return congestionName(o.TCPCongestion)
}

// NotSentLowat resolves TCPNotSentLowat: the bytes to set, or 0 to leave the
// system default.
func (o *XrayOptions) NotSentLowat() int {
	return notSentLowat(o.TCPNotSentLowat)
}

func notSentLowat(configured int) int {
	switch {
	case configured < 0:
		return 0
	case configured == 0:
		return DefaultTCPNotSentLowat
	}
	return configured
}

type FallBackConfigForXray struct {
	SNI              string `json:"SNI"`
	Alpn             string `json:"Alpn"`
	Path             string `json:"Path"`
	Dest             string `json:"Dest"`
	ProxyProtocolVer uint64 `json:"ProxyProtocolVer"`
}

func NewXrayOptions() *XrayOptions {
	return &XrayOptions{
		EnableProxyProtocol: false,
		EnableDNS:           false,
		DNSType:             "AsIs",
		EnableUot:           false,
		EnableTFO:           false,
		DisableIVCheck:      false,
		DisableSniffing:     false,
		EnableFallback:      false,
	}
}
