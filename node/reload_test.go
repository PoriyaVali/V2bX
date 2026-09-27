package node

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/common/task"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
)

// reloadCore is a core whose node operations can be made to fail or block,
// and which records what is registered so a test can see what the node really
// looks like from the core's side.
type reloadCore struct {
	stubCore
	mu       sync.Mutex
	nodes    map[string]*panel.NodeInfo
	failAdd  int
	failDel  int
	addCalls int
	// gate, when set, blocks AddNode until it is closed.
	gate chan struct{}
	// limiterAtDel records whether the node's limiter still existed when
	// DelNode ran.
	limiterAtDel []bool
}

func (r *reloadCore) AddNode(tag string, info *panel.NodeInfo, _ *conf.Options) error {
	r.mu.Lock()
	gate := r.gate
	r.mu.Unlock()
	if gate != nil {
		<-gate
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addCalls++
	if r.failAdd > 0 {
		r.failAdd--
		return errors.New("port busy")
	}
	if r.nodes == nil {
		r.nodes = map[string]*panel.NodeInfo{}
	}
	if r.nodes[tag] != nil {
		return errors.New("node already exists")
	}
	r.nodes[tag] = info
	return nil
}

func (r *reloadCore) DelNode(tag string) error {
	_, err := limiter.GetLimiter(tag)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limiterAtDel = append(r.limiterAtDel, err == nil)
	if r.failDel > 0 {
		r.failDel--
		return errors.New("busy")
	}
	if r.nodes[tag] == nil {
		return errors.New("the node is not have")
	}
	delete(r.nodes, tag)
	return nil
}

func (r *reloadCore) AddUsers(p *vCore.AddUsersParams) (int, error) { return len(p.Users), nil }

// servedPort is the port the core is serving tag on, or 0 if it is not.
func (r *reloadCore) servedPort(tag string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := r.nodes[tag]; n != nil {
		return n.Common.ServerPort
	}
	return 0
}

func (r *reloadCore) set(f func(r *reloadCore)) {
	r.mu.Lock()
	f(r)
	r.mu.Unlock()
}

// startedController starts a real controller against the fake panel and closes
// it at the end of the test.
func startedController(t *testing.T, f *fakePanel, core vCore.Core, opts *conf.Options) *Controller {
	t.Helper()
	limiter.Init()
	api, err := panel.New(&conf.ApiConfig{
		APIHost: f.srv.URL, NodeID: 1, Key: "k", NodeType: "shadowsocks", Timeout: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := NewController(core, api, opts)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// 🔴 A reload that fails after the old node is gone must be retried on the next
// poll. It used to record the new config first, so the retry compared equal to
// it, was taken for a threshold-only change, and the node stayed out of the
// core until the panel's config changed again.
func TestReload_FailedAddNodeIsRetried(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{})

	f.setPort(5555)
	core.set(func(r *reloadCore) { r.failAdd = 1 })
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 0 {
		t.Fatalf("setup: AddNode was meant to fail, but the core serves port %d", got)
	}

	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 5555 {
		t.Fatalf("after a failed reload the next poll must bring the node back on 5555; core serves %d", got)
	}
}

// The same when the panel answers "unchanged" (304 / same body) on the next
// poll: the node still has to come back.
func TestReload_RetriedEvenWhenPanelSaysUnchanged(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{})

	f.setPort(5555)
	core.set(func(r *reloadCore) { r.failAdd = 1 })
	_ = c.nodeInfoMonitor()
	// Pretend the panel client remembered the config it was sent.
	if n, err := c.apiClient.GetNodeInfo(); err != nil || n == nil {
		t.Fatalf("setup: prime the client's cache: %v %v", n, err)
	}
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 5555 {
		t.Fatalf("node not rebuilt after the panel said unchanged; core serves %d", got)
	}
}

// And when the panel goes back to the config the node had before: that looks
// like "nothing changed" next to the old config, but the node is still down.
func TestReload_RetriedWhenPanelRevertsTheConfig(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{})

	f.setPort(5555)
	core.set(func(r *reloadCore) { r.failAdd = 1 })
	_ = c.nodeInfoMonitor()
	f.setPort(1234)
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 1234 {
		t.Fatalf("node not rebuilt after the panel reverted its config; core serves %d", got)
	}
}

// A DelNode that fails leaves the old node running; the new config must still
// be applied on a later poll rather than being mistaken for the current one.
func TestReload_FailedDelNodeIsRetried(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{})

	f.setPort(5555)
	core.set(func(r *reloadCore) { r.failDel = 1 })
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 1234 {
		t.Fatalf("setup: DelNode failed, so the old node should still run; core serves %d", got)
	}
	_ = c.nodeInfoMonitor()
	if got := core.servedPort(c.tag); got != 5555 {
		t.Fatalf("new config never applied after a failed DelNode; core serves %d", got)
	}
}

// 🔴 On a node with a Name, a user who joined in the same poll as a config
// change was never added to the limiter and was refused as unknown - for good,
// since every later poll saw them as already there.
func TestReload_NamedNodeLetsInAUserWhoJoinedDuringTheReload(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{Name: "named-node"})

	f.setPort(5555)
	f.setUsers([]panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}})
	_ = c.nodeInfoMonitor()
	_ = c.nodeInfoMonitor()

	if _, rej := c.limiter.CheckLimit(format.UserTag(c.tag, "u2"), "10.0.0.2", true, true); rej {
		t.Fatal("a user who joined together with a config change is refused by the limiter")
	}
}

// ...and one who left in that poll is no longer admitted.
func TestReload_UserWhoLeftDuringTheReloadIsRefused(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{Name: "named-node"})

	f.setPort(5555)
	f.setUsers([]panel.UserInfo{{Id: 1, Uuid: "u1"}})
	_ = c.nodeInfoMonitor()

	if _, rej := c.limiter.CheckLimit(format.UserTag(c.tag, "u2"), "10.0.0.2", true, true); !rej {
		t.Fatal("a user removed together with a config change is still admitted by the limiter")
	}
}

// A reload keeps the limiter's device registrations. It used to build a new
// limiter, so a device_limit=1 user reconnecting from the address they were
// already counted on was counted a second time against their own device.
func TestReload_KeepsDeviceRegistrations(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1", DeviceLimit: 1}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{})
	key := format.UserTag(c.tag, "u1")

	if _, rej := c.limiter.CheckLimit(key, "10.0.0.1", true, true); rej {
		t.Fatal("setup: first device refused")
	}
	// The panel now counts that device, and the node config changes.
	f.setAlive(map[int]int{1: 1})
	f.setPort(5555)
	_ = c.nodeInfoMonitor()

	if _, rej := c.limiter.CheckLimit(key, "10.0.0.1", true, true); rej {
		t.Fatal("after a reload the user's own device is refused as a second device")
	}
	if _, rej := c.limiter.CheckLimit(key, "10.0.0.9", true, true); !rej {
		t.Fatal("a genuinely new device must still be refused at device_limit=1")
	}
}

// Close stops every task. The status report was left out and ran for the rest
// of the process's life, one more copy after every config reload.
func TestClose_StopsEveryTask(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	c := startedController(t, f, &reloadCore{}, &conf.Options{})
	tasks := map[string]*task.Task{
		"nodeInfoMonitor": c.nodeInfoMonitorPeriodic,
		"userReport":      c.userReportPeriodic,
		"statusReport":    c.statusReportPeriodic,
	}
	for name, tk := range tasks {
		if tk == nil || !tk.Running() {
			t.Fatalf("setup: %s not running", name)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	for name, tk := range tasks {
		if tk.Running() {
			t.Errorf("%s still running after Close", name)
		}
	}
}

// Close takes the node out of the core before it drops the limiter, so no
// connection can reach a live node that has no limiter.
func TestClose_RemovesNodeBeforeLimiter(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	core.mu.Lock()
	seen := append([]bool(nil), core.limiterAtDel...)
	core.mu.Unlock()
	if len(seen) != 1 || !seen[0] {
		t.Fatalf("limiter present at DelNode = %v, want [true]", seen)
	}
	if _, err := limiter.GetLimiter(c.tag); err == nil {
		t.Fatal("limiter left behind after Close")
	}
}

// A reload that is under way when Close runs must not put the node back into
// the core afterwards.
func TestClose_WaitsForAReloadInProgress(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{})

	gate := make(chan struct{})
	core.set(func(r *reloadCore) { r.gate = gate })
	f.setPort(5555)
	reloaded := make(chan struct{})
	go func() { _ = c.nodeInfoMonitor(); close(reloaded) }()
	// Let the reload reach AddNode and block there.
	waitFor(t, "the reload to take the old node out", func() bool { return core.servedPort(c.tag) == 0 })

	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while a reload was still adding the node")
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	<-reloaded
	<-closed
	if got := core.servedPort(c.tag); got != 0 {
		t.Fatalf("node is back in the core on port %d after Close", got)
	}
	if c.nodeInfoMonitorPeriodic.Running() {
		t.Fatal("the reload restarted its task after Close")
	}
}

// The report goroutine reads the node's state while the node-info goroutine
// replaces it. Run under -race (as CI does); this used to report a race on
// every reload.
func TestReportAndReloadDoNotRace(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	c := startedController(t, f, &reloadCore{}, &conf.Options{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			_ = c.reportUserTrafficTask()
			_ = c.reportNodeStatusTask()
		}
	}()
	for i := 0; i < 20; i++ {
		f.setPort(2000 + i)
		_ = c.nodeInfoMonitor()
	}
	<-done
}
