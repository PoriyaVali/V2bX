package node

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
)

// flakyCore fails AddNode a set number of times, then behaves, and records
// what it was asked to do.
type flakyCore struct {
	stubCore
	mu          sync.Mutex
	failAdds    int
	addedUsers  int
	nodes       map[string]bool
	delNodeTags []string
	failUsers   bool
}

func (f *flakyCore) AddNode(tag string, _ *panel.NodeInfo, _ *conf.Options) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAdds > 0 {
		f.failAdds--
		return errors.New("port busy")
	}
	if f.nodes == nil {
		f.nodes = map[string]bool{}
	}
	if f.nodes[tag] {
		return errors.New("node already exists")
	}
	f.nodes[tag] = true
	return nil
}

func (f *flakyCore) DelNode(tag string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.nodes, tag)
	f.delNodeTags = append(f.delNodeTags, tag)
	return nil
}

func (f *flakyCore) AddUsers(p *vCore.AddUsersParams) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failUsers {
		return 0, errors.New("inbound gone")
	}
	f.addedUsers += len(p.Users)
	return len(p.Users), nil
}

func (f *flakyCore) usersAdded() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addedUsers
}

func fastRetries(t *testing.T) {
	t.Helper()
	oldInit, oldMax := retryInitialDelay, retryMaxDelay
	retryInitialDelay, retryMaxDelay = 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { retryInitialDelay, retryMaxDelay = oldInit, oldMax })
}

func nodeConfigFor(f *fakePanel) []conf.NodeConfig {
	return []conf.NodeConfig{{
		ApiConfig: conf.ApiConfig{APIHost: f.srv.URL, NodeID: 1, Key: "k", NodeType: "shadowsocks", Timeout: 5},
		Options:   conf.Options{},
	}}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (n *Node) controllerAt(i int) *Controller {
	n.mu.Lock()
	defer n.mu.Unlock()
	if i >= len(n.controllers) {
		return nil
	}
	return n.controllers[i]
}

// A node that fails to start is retried until it comes up. It used to be
// dropped for the life of the process while the log said "keep retrying".
func TestNodeStart_FailedNodeIsRetriedUntilItStarts(t *testing.T) {
	fastRetries(t)
	limiter.Init()
	users := []panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}}
	f := newFakePanel(t, 0, users)
	// ETags on: a retry that reused the first client would be told "304,
	// nothing changed" for the users and come up with nobody on the node.
	f.enableEtag()
	core := &flakyCore{failAdds: 2}

	n := New()
	if err := n.Start(nodeConfigFor(f), core); err != nil {
		t.Fatalf("Start must not fail while a retry is pending: %v", err)
	}
	t.Cleanup(n.Close)
	waitFor(t, "the node to start on a retry", func() bool { return n.controllerAt(0) != nil })
	if got := core.usersAdded(); got != len(users) {
		t.Fatalf("retried node came up with %d users, want %d", got, len(users))
	}
}

// Close must cope with a node that never started (its slot is nil), which is
// exactly what a config reload finds after a failed start.
func TestNodeClose_SkipsNodeThatNeverStarted(t *testing.T) {
	fastRetries(t)
	limiter.Init()
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	})
	f := &fakePanel{}
	f.srv = newTestServer(t, mux)

	n := New()
	if err := n.Start(nodeConfigFor(f), &flakyCore{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, "a retry attempt", func() bool { return hits.Load() >= 2 })
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung while a retry was pending")
	}
	after := hits.Load()
	time.Sleep(150 * time.Millisecond)
	if hits.Load() != after {
		t.Fatal("retries kept hitting the panel after Close")
	}
}

// A start that fails after AddNode must undo it, or every retry would fail
// with "already exists" and the node would never come back.
func TestControllerStart_FailureUndoesAddNodeAndLimiter(t *testing.T) {
	limiter.Init()
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &flakyCore{failUsers: true}
	api, err := panel.New(&conf.ApiConfig{APIHost: f.srv.URL, NodeID: 1, Key: "k", NodeType: "shadowsocks", Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	c := NewController(core, api, &conf.Options{})
	if err := c.Start(); err == nil {
		t.Fatal("Start should fail when AddUsers fails")
	}
	core.mu.Lock()
	leftover := len(core.nodes)
	core.mu.Unlock()
	if leftover != 0 {
		t.Fatalf("%d node(s) left registered in the core after a failed start", leftover)
	}
	if _, err := limiter.GetLimiter(c.tag); err == nil {
		t.Fatal("limiter left behind after a failed start")
	}
}

func newTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}
