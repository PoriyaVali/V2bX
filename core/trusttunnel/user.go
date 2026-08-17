package trusttunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
)

// The endpoint authenticates with a username and password, and a subscriber has
// exactly one secret the panel already issued them. Using the uuid for both
// keeps the subscription link to one value and means traffic comes back keyed
// by something we can map to a panel id.
func credentialsFor(u panel.UserInfo) (string, string) { return u.Uuid, u.Uuid }

func (t *TrustTunnel) AddUsers(p *vCore.AddUsersParams) (added int, err error) {
	t.mu.Lock()
	n := t.nodes[p.Tag]
	for _, u := range p.Users {
		t.usersMap[u.Uuid] = u.Id
	}
	t.mu.Unlock()

	if n == nil {
		return len(p.Users), nil
	}

	n.mu.Lock()
	for _, u := range p.Users {
		name, pass := credentialsFor(u)
		n.users[name] = pass
	}
	n.mu.Unlock()

	if err := n.applyUsers(); err != nil {
		return 0, fmt.Errorf("trusttunnel: add users to %s: %w", p.Tag, err)
	}
	return len(p.Users), nil
}

func (t *TrustTunnel) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	t.mu.Lock()
	n := t.nodes[tag]
	for _, u := range users {
		delete(t.usersMap, u.Uuid)
	}
	t.mu.Unlock()

	if n == nil {
		return nil
	}

	n.mu.Lock()
	for _, u := range users {
		name, _ := credentialsFor(u)
		delete(n.users, name)
	}
	n.mu.Unlock()

	if err := n.applyUsers(); err != nil {
		return fmt.Errorf("trusttunnel: remove users from %s: %w", tag, err)
	}
	return nil
}

// applyUsers rewrites the credentials file and signals the endpoint to reload.
//
// SIGHUP rather than a restart: the endpoint swaps its client list in place, so
// subscribers already connected stay connected. Verified against a live
// endpoint - the process id is unchanged across a reload.
//
// The file is written through a temporary file and renamed, because the
// endpoint may read it at any moment and a half-written file would parse as a
// shorter user list. The endpoint keeps its previous list when a reload fails,
// so the worst case is a stale list rather than everyone locked out.
func (n *node) applyUsers() error {
	if err := n.writeCredentials(); err != nil {
		return err
	}

	n.mu.Lock()
	cmd := n.cmd
	n.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil // not running; the file is in place for when it starts
	}
	return cmd.Process.Signal(syscall.SIGHUP)
}

func (n *node) writeCredentials() error {
	n.mu.Lock()
	users := make(map[string]string, len(n.users))
	for k, v := range n.users {
		users[k] = v
	}
	dir := n.dir
	n.mu.Unlock()

	var b strings.Builder
	for name, pass := range users {
		// A uuid contains nothing that needs escaping, and anything that did
		// would be a sign the panel sent something unexpected - so reject
		// rather than emit TOML that means something else.
		if strings.ContainsAny(name, "\"\\\n") || strings.ContainsAny(pass, "\"\\\n") {
			return fmt.Errorf("refusing to write credential containing quotes or newlines")
		}
		fmt.Fprintf(&b, "[[client]]\nusername = %q\npassword = %q\n\n", name, pass)
	}

	final := filepath.Join(dir, "credentials.toml")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("replace credentials: %w", err)
	}
	return nil
}

// usage is what the endpoint's drain returns: username -> bytes each way.
type usage struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

func (t *TrustTunnel) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	t.mu.RLock()
	n := t.nodes[tag]
	t.mu.RUnlock()
	if n == nil {
		return nil, nil
	}

	drained, err := n.drain(reset)
	if err != nil {
		return nil, fmt.Errorf("trusttunnel: read traffic from %s: %w", tag, err)
	}
	if len(drained) == 0 {
		return nil, nil
	}

	out := make([]panel.UserTraffic, 0, len(drained))
	t.mu.RLock()
	defer t.mu.RUnlock()
	for name, u := range drained {
		uid, ok := t.usersMap[name]
		if !ok {
			continue // user removed since the traffic was recorded
		}
		out = append(out, panel.UserTraffic{
			UID:      uid,
			Upload:   u.Uplink,
			Download: u.Downlink,
		})
	}
	return out, nil
}

// drain reads the endpoint's per-user counters, clearing them unless asked not
// to. Clearing is the normal path: the panel wants what was used since it last
// asked, and anything read here is about to be reported.
func (n *node) drain(reset bool) (map[string]usage, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/user-traffic", n.metricsPort)
	if !reset {
		url += "?reset=0"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// The endpoint binds its metrics port to loopback and refuses to
			// serve user data anywhere else, so there is nothing to reach
			// through a proxy - and inheriting one from the environment would
			// send the subscriber list somewhere it should never go.
			Proxy:       nil,
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("drain returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out map[string]usage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode drain response: %w", err)
	}
	return out, nil
}

// freePort asks the kernel for an unused port and hands back the number.
//
// There is a gap between closing this listener and the endpoint binding it, but
// the alternative - a fixed port per node - collides the moment two nodes run
// on one host, which is the normal case.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
