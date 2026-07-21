package node

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// ---------------------------------------------------------------------------
// Harness: a fake panel + a stub core, so the tests below drive the real
// nodeInfoMonitor / reportUserTrafficTask and assert on what actually goes out
// over the wire to /api/v1/server/UniProxy/alive.
// ---------------------------------------------------------------------------

type stubCore struct {
	mu      sync.Mutex
	traffic []panel.UserTraffic
}

func (s *stubCore) Start() error                                             { return nil }
func (s *stubCore) Close() error                                             { return nil }
func (s *stubCore) AddNode(string, *panel.NodeInfo, *conf.Options) error     { return nil }
func (s *stubCore) DelNode(string) error                                     { return nil }
func (s *stubCore) AddUsers(p *vCore.AddUsersParams) (int, error)            { return len(p.Users), nil }
func (s *stubCore) DelUsers([]panel.UserInfo, string, *panel.NodeInfo) error { return nil }
func (s *stubCore) Protocols() []string                                      { return []string{"shadowsocks"} }
func (s *stubCore) Type() string                                             { return "stub" }

func (s *stubCore) setTraffic(t []panel.UserTraffic) {
	s.mu.Lock()
	s.traffic = t
	s.mu.Unlock()
}

func (s *stubCore) GetUserTrafficSlice(string, bool) ([]panel.UserTraffic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.traffic, nil
}

type fakePanel struct {
	mu            sync.Mutex
	users         []panel.UserInfo
	capturedAlive map[int][]string
	srv           *httptest.Server
	// etag makes the user endpoint answer 304 when the caller already holds the
	// current list, like the real panel. Off by default so tests that only care
	// about "here is the list now" keep getting a plain 200.
	etag bool
}

func newFakePanel(t *testing.T, deviceOnlineMinKB int, users []panel.UserInfo) *fakePanel {
	t.Helper()
	f := &fakePanel{users: users}
	mux := http.NewServeMux()

	// Byte-identical every poll, so GetNodeInfo reports "unchanged" after the
	// first call and nodeInfoMonitor takes the compare-users path, as in production.
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"server_port":1234,"cipher":"aes-128-gcm","base_config":`+
			`{"push_interval":41,"pull_interval":31,"node_report_min_traffic":0,"device_online_min_traffic":%d}}`,
			deviceOnlineMinKB)
	})
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		body, _ := json.Marshal(panel.UserListBody{Users: f.users})
		useEtag := f.etag
		f.mu.Unlock()
		if useEtag {
			tag := fmt.Sprintf(`"%x"`, sha1.Sum(body))
			w.Header().Set("ETag", tag)
			if r.Header.Get("If-None-Match") == tag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	mux.HandleFunc("/api/v1/server/UniProxy/alivelist", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"alive":{}}`))
	})
	mux.HandleFunc("/api/v1/server/UniProxy/alive", func(w http.ResponseWriter, r *http.Request) {
		var got map[int][]string
		_ = json.NewDecoder(r.Body).Decode(&got)
		f.mu.Lock()
		f.capturedAlive = got
		f.mu.Unlock()
		w.Write([]byte(`{"data":true}`))
	})
	mux.HandleFunc("/api/v1/server/UniProxy/push", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":true}`))
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePanel) setUsers(u []panel.UserInfo) {
	f.mu.Lock()
	f.users = u
	f.mu.Unlock()
}

// enableEtag switches the user endpoint over to conditional replies, so an
// unchanged list comes back as 304 instead of a fresh 200.
func (f *fakePanel) enableEtag() {
	f.mu.Lock()
	f.etag = true
	f.mu.Unlock()
}

func (f *fakePanel) reportedOnline() map[int][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.capturedAlive
}

// newSyncedController builds a controller wired to the fake panel and runs one
// poll, so it is in the same state as a live node that has just started.
func newSyncedController(t *testing.T, f *fakePanel, core vCore.Core) *Controller {
	t.Helper()
	limiter.Init()
	api, err := panel.New(&conf.ApiConfig{
		APIHost: f.srv.URL, NodeID: 1, Key: "k", NodeType: "shadowsocks", Timeout: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := NewController(core, api, &conf.Options{})
	// startTasks() normally creates these; pre-seed them with the intervals the
	// fake panel serves so the "interval changed?" checks are no-ops.
	noop := func() error { return nil }
	c.nodeInfoMonitorPeriodic = &task.Task{Interval: 31 * time.Second, Execute: noop}
	c.userReportPeriodic = &task.Task{Interval: 41 * time.Second, Execute: noop}
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { limiter.DeleteLimiter(c.tag) })
	return c
}

func limiterDeviceLimit(t *testing.T, c *Controller, uuid string) int64 {
	t.Helper()
	v, ok := c.limiter.UserLimitInfo.Load(format.UserTag(c.tag, uuid))
	if !ok {
		t.Fatalf("no UserLimitInfo for %s", uuid)
	}
	return v.(*limiter.UserLimitInfo).DeviceLimit.Load()
}

// ---------------------------------------------------------------------------

// End-to-end: an admin edits a user's device_limit in the panel and the node
// must enforce the new value on its next poll — without the user ever being
// removed from the core (which would drop their live connections).
func TestPoll_DeviceLimitChangeReachesTheLimiter(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 10, DeviceLimit: 2}})
	c := newSyncedController(t, f, &stubCore{})

	if got := limiterDeviceLimit(t, c, "u1"); got != 2 {
		t.Fatalf("setup: limiter device_limit = %d, want 2", got)
	}

	f.setUsers([]panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 10, DeviceLimit: 5}})
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}

	if got := limiterDeviceLimit(t, c, "u1"); got != 5 {
		t.Fatalf("panel raised device_limit to 5 but the limiter still enforces %d", got)
	}
}

// A limit-only edit is not a membership change: it must produce no added/deleted
// set, because those drive DelUsers/AddUsers on the core and would disconnect
// the user every time an admin touched their plan.
func TestCompareUserList_LimitEditIsNotMembershipChange(t *testing.T) {
	old := []panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 10, DeviceLimit: 2}}
	new := []panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 99, DeviceLimit: 5}}

	deleted, added := compareUserList(old, new)
	if len(deleted) != 0 || len(added) != 0 {
		t.Fatalf("a limit edit was treated as membership churn (deleted=%d added=%d) — "+
			"the user would be torn out of the core and lose their connections", len(deleted), len(added))
	}
}

func TestCompareUserList_DetectsJoinAndLeave(t *testing.T) {
	old := []panel.UserInfo{{Id: 1, Uuid: "stays"}, {Id: 2, Uuid: "leaves"}}
	new := []panel.UserInfo{{Id: 1, Uuid: "stays"}, {Id: 3, Uuid: "joins"}}

	deleted, added := compareUserList(old, new)
	if len(deleted) != 1 || deleted[0].Uuid != "leaves" {
		t.Errorf("deleted = %+v, want [leaves]", deleted)
	}
	if len(added) != 1 || added[0].Uuid != "joins" {
		t.Errorf("added = %+v, want [joins]", added)
	}
}

// The device_online_min_traffic gate must be monotonic: more traffic can only
// make a device MORE likely to be counted. It used to be expressed as a deny-set
// ("skip users below the threshold"), which inverted it at the zero-byte edge —
// the core omits users with 0 bytes from the traffic slice entirely, so they were
// never added to the deny-set and got reported, while a genuinely active user
// just under the threshold did not. A dead connection consumed a device slot; a
// live, lightly-used one did not.
func TestReport_OnlineGateIsNotInverted(t *testing.T) {
	const gateKB = 64
	users := []panel.UserInfo{
		{Id: 1, Uuid: "idle", DeviceLimit: 5},  // 0 bytes  → absent from the traffic slice
		{Id: 2, Uuid: "light", DeviceLimit: 5}, // 30 KB    → present, below the gate
		{Id: 3, Uuid: "heavy", DeviceLimit: 5}, // 5 MB     → present, above the gate
	}
	f := newFakePanel(t, gateKB, users)
	core := &stubCore{}
	c := newSyncedController(t, f, core)

	core.setTraffic([]panel.UserTraffic{
		{UID: 2, Upload: 15_000, Download: 15_000},       // 30 KB
		{UID: 3, Upload: 2_500_000, Download: 2_500_000}, // 5 MB
	})
	for i, u := range users {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		if _, rej := c.limiter.CheckLimit(format.UserTag(c.tag, u.Uuid), ip, true, true); rej {
			t.Fatalf("%s rejected during setup", u.Uuid)
		}
	}

	if err := c.reportUserTrafficTask(); err != nil {
		t.Fatal(err)
	}
	got := f.reportedOnline()

	if _, ok := got[3]; !ok {
		t.Errorf("the 5 MB user is above the %d KB gate and must be reported online; got %v", gateKB, got)
	}
	if _, ok := got[1]; ok {
		t.Errorf("the 0-byte user is below the gate and must NOT be reported online (it would eat a "+
			"device slot); got %v", got)
	}
	if _, ok := got[2]; ok {
		t.Errorf("the 30 KB user is below the %d KB gate and must not be reported; got %v", gateKB, got)
	}
}

// With the gate disabled (0) every online device is reported, regardless of traffic.
func TestReport_GateDisabledReportsEveryOnlineDevice(t *testing.T) {
	users := []panel.UserInfo{{Id: 1, Uuid: "idle", DeviceLimit: 5}, {Id: 2, Uuid: "busy", DeviceLimit: 5}}
	f := newFakePanel(t, 0, users)
	core := &stubCore{}
	c := newSyncedController(t, f, core)
	c.Options.DeviceOnlineMinTraffic = 0

	core.setTraffic([]panel.UserTraffic{{UID: 2, Upload: 1, Download: 1}})
	for i, u := range users {
		ip := fmt.Sprintf("10.0.1.%d", i+1)
		c.limiter.CheckLimit(format.UserTag(c.tag, u.Uuid), ip, true, true)
	}

	if err := c.reportUserTrafficTask(); err != nil {
		t.Fatal(err)
	}
	got := f.reportedOnline()
	if len(got) != 2 {
		t.Fatalf("gate disabled: every online device must be reported, got %v", got)
	}
}
