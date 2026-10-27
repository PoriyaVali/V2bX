package conf

// MihomoConfig configures isolated server listeners from the user's Mihomo fork.
// It does not enable Mihomo's global HTTP controller or client proxy ports.
type MihomoConfig struct {
	AllowPrivateDestinations bool `json:"AllowPrivateDestinations"`
	DialTimeout              int  `json:"DialTimeout"`
	UDPTimeout               int  `json:"UDPTimeout"`
}

func NewMihomoConfig() *MihomoConfig {
	return &MihomoConfig{DialTimeout: 10, UDPTimeout: 120}
}

type MihomoOptions struct {
	JLSUpstream struct {
		Addr string `json:"Addr"`
		SNI  string `json:"SNI"`
	} `json:"JLSUpstream"`
}
