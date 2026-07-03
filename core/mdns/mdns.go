package mdns

import (
	"sync"

	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	mdnssrv "masterdnsvpn-go/server"
)

var _ vCore.Core = (*Mdns)(nil)

// node is one running MasterDnsVPN tunnel bound to a panel node tag.
type node struct {
	server *mdnssrv.Server
}

// Mdns is the V2bX core wrapping the MasterDnsVPN DNS-tunnel server. The
// embedded server handles per-user auth and metering; this core maps panel
// UUIDs to numeric UIDs for traffic reporting and manages node lifecycles.
type Mdns struct {
	mu       sync.RWMutex
	nodes    map[string]*node
	usersMap map[string]int // uuid -> panel UID
}

func init() {
	vCore.RegisterCore("mdns", New)
}

func New(_ *conf.CoreConfig) (vCore.Core, error) {
	return &Mdns{
		nodes:    make(map[string]*node),
		usersMap: make(map[string]int),
	}, nil
}

func (m *Mdns) Type() string { return "mdns" }

func (m *Mdns) Protocols() []string { return []string{"mdns"} }

func (m *Mdns) Start() error { return nil }

func (m *Mdns) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.nodes {
		_ = n.server.Close()
	}
	m.nodes = make(map[string]*node)
	m.usersMap = make(map[string]int)
	return nil
}
