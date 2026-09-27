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
			Handshake: 4,
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
