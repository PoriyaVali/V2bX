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
	mu    sync.RWMutex
	nodes map[string]*node
	// users is tag -> uuid -> panel UID. It was one uuid-keyed map for every
	// node, so removing a subscriber from one node erased their id for all of
	// them, and their traffic on the nodes they were still on was dropped as
	// "unknown user" at the next report.
	users map[string]map[string]int
	// carried holds traffic a node had counted but not yet reported when it
	// was removed - a node reload closes the tunnel, and its counters with it.
	// The next report for the tag sends it.
	carried map[string]map[string][2]int64 // tag -> uuid -> [up, down]
}

func init() {
	vCore.RegisterCore("mdns", New)
}

func New(_ *conf.CoreConfig) (vCore.Core, error) {
	return &Mdns{
		nodes:   make(map[string]*node),
		users:   make(map[string]map[string]int),
		carried: make(map[string]map[string][2]int64),
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
	m.users = make(map[string]map[string]int)
	m.carried = make(map[string]map[string][2]int64)
	return nil
}
