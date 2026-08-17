// Package trusttunnel runs the TrustTunnel endpoint as a V2bX core.
//
// Every other core in this tree is a Go library linked into V2bX, so its
// Start() has nothing to do. This one is different: the endpoint is a separate
// Rust binary, so the core owns a child process per node and has to keep it
// alive, feed it users through its config file, and read traffic back over its
// metrics port.
//
// Two things are deliberately not done here. Config files are produced by the
// setup wizard shipped beside the endpoint rather than written by hand, so
// generation stays correct across endpoint releases. And user changes are
// applied with SIGHUP rather than a restart, because the endpoint reloads its
// client list in place - a restart would drop every connected subscriber every
// time the panel syncs.
package trusttunnel

import (
	"fmt"
	"os"
	"sync"

	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
)

var _ vCore.Core = (*TrustTunnel)(nil)

// TrustTunnel maps panel nodes onto endpoint processes.
type TrustTunnel struct {
	mu    sync.RWMutex
	nodes map[string]*node
	// uuid -> panel UID. Traffic comes back from the endpoint keyed by the
	// username we gave it, which is the subscriber's uuid, and the panel wants
	// the numeric id.
	usersMap map[string]int
	// Where per-node working directories are created. Each holds the generated
	// vpn.toml, hosts.toml, credentials.toml and certs.
	workDir string
	// Path to the endpoint and wizard binaries.
	binDir string
}

func init() {
	vCore.RegisterCore("trusttunnel", New)
}

// Paths are taken from the environment rather than the core config so this
// core needs no new config schema to be usable, and so an operator who put the
// binaries somewhere else can say so without a rebuild.
func New(_ *conf.CoreConfig) (vCore.Core, error) {
	work := envOr("V2BX_TRUSTTUNNEL_DIR", "/etc/V2bX/trusttunnel")
	// Where install.sh unpacks them, beside V2bX itself. A default pointing
	// somewhere the installer does not write is a node that configures cleanly
	// and then cannot start.
	bin := envOr("V2BX_TRUSTTUNNEL_BIN", "/usr/local/V2bX")
	return &TrustTunnel{
		nodes:    make(map[string]*node),
		usersMap: make(map[string]int),
		workDir:  work,
		binDir:   bin,
	}, nil
}

func (t *TrustTunnel) Type() string { return "trusttunnel" }

func (t *TrustTunnel) Protocols() []string { return []string{"trusttunnel"} }

// Start checks the pieces exist before any node tries to use them.
//
// Nodes are started by AddNode as the panel reports them, so there is nothing
// to launch here - but a missing binary discovered now is a clear error at
// startup, where the same thing discovered later reads as a node that silently
// never comes up.
func (t *TrustTunnel) Start() error {
	for _, b := range []string{endpointBin, wizardBin} {
		p := t.binPath(b)
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("trusttunnel: %s not found at %s: %w", b, p, err)
		}
	}
	if err := os.MkdirAll(t.workDir, 0o700); err != nil {
		return fmt.Errorf("trusttunnel: create work dir %s: %w", t.workDir, err)
	}
	return nil
}

// Close stops every endpoint. Supervision is cancelled first so a process going
// away during shutdown is not mistaken for a crash and restarted underneath us.
func (t *TrustTunnel) Close() error {
	t.mu.Lock()
	nodes := t.nodes
	t.nodes = make(map[string]*node)
	t.usersMap = make(map[string]int)
	t.mu.Unlock()

	for _, n := range nodes {
		n.shutdown()
	}
	return nil
}
