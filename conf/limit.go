package conf

type LimitConfig struct {
	EnableRealtime bool `json:"EnableRealtime"`
	SpeedLimit     int  `json:"SpeedLimit"`
	IPLimit        int  `json:"DeviceLimit"`
	// ConnLimit caps one user's simultaneous connections on a node: 0 = the
	// default (DefaultConnLimit), negative = no cap. It was parsed and never
	// used, so a limit an operator set did nothing. Enforced by the sing and
	// xray cores. The standalone hysteria2 core cannot: its library reports a
	// user's streams but offers no way to refuse one (a hysteria2 node on the
	// sing core is capped like any other).
	ConnLimit               int                      `json:"ConnLimit"`
	EnableIpRecorder        bool                     `json:"EnableIpRecorder"`
	IpRecorderConfig        *IpReportConfig          `json:"IpRecorderConfig"`
	EnableDynamicSpeedLimit bool                     `json:"EnableDynamicSpeedLimit"`
	DynamicSpeedLimitConfig *DynamicSpeedLimitConfig `json:"DynamicSpeedLimitConfig"`
}

type RecorderConfig struct {
	Url     string `json:"Url"`
	Token   string `json:"Token"`
	Timeout int    `json:"Timeout"`
}

type RedisConfig struct {
	Address  string `json:"Address"`
	Password string `json:"Password"`
	Db       int    `json:"Db"`
	Expiry   int    `json:"Expiry"`
}

type IpReportConfig struct {
	Periodic       int             `json:"Periodic"`
	Type           string          `json:"Type"`
	RecorderConfig *RecorderConfig `json:"RecorderConfig"`
	RedisConfig    *RedisConfig    `json:"RedisConfig"`
	EnableIpSync   bool            `json:"EnableIpSync"`
}

type DynamicSpeedLimitConfig struct {
	Periodic   int   `json:"Periodic"`
	Traffic    int64 `json:"Traffic"`
	SpeedLimit int   `json:"SpeedLimit"`
	ExpireTime int   `json:"ExpireTime"`
}

// DefaultConnLimit is generous on purpose: a browser holds at most 256 sockets
// and a phone far fewer, so this never touches honest use. It exists so one
// runaway client - a scanner, a torrent client left unbounded, a looping app -
// cannot hold thousands of connections and slow the node for everyone else.
const DefaultConnLimit = 1024

// MaxConnsPerUser resolves ConnLimit; 0 means no cap.
func (l *LimitConfig) MaxConnsPerUser() int {
	switch {
	case l.ConnLimit < 0:
		return 0
	case l.ConnLimit == 0:
		return DefaultConnLimit
	}
	return l.ConnLimit
}
