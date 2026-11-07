package conf

type Hysteria2Config struct {
	LogConfig Hysteria2LogConfig `json:"Log"`
	// AllowPrivateDestinations lets users reach loopback, private and
	// link-local addresses through the node, as on the sing and Mihomo
	// cores. Off by default: those are the node's own services and its
	// hosting provider's internal network.
	AllowPrivateDestinations bool `json:"AllowPrivateDestinations"`
}

type Hysteria2LogConfig struct {
	Level string `json:"Level"`
}

func NewHysteria2Config() *Hysteria2Config {
	return &Hysteria2Config{
		LogConfig: Hysteria2LogConfig{
			Level: "error",
		},
	}
}
