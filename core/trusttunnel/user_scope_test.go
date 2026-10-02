package trusttunnel

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
)

func TestUserTrafficMappingSurvivesRemovalOnAnotherNode(t *testing.T) {
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user-traffic" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"shared-uuid":{"uplink":123,"downlink":456}}`))
	}))
	defer metrics.Close()
	core, err := New(&conf.CoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	tt := core.(*TrustTunnel)
	port := metrics.Listener.Addr().(*net.TCPAddr).Port
	for _, tag := range []string{"a", "b"} {
		tt.nodes[tag] = &node{dir: t.TempDir(), users: make(map[string]string), metricsPort: port}
	}
	userA := panel.UserInfo{Id: 1, Uuid: "shared-uuid"}
	userB := panel.UserInfo{Id: 2, Uuid: "shared-uuid"}
	for _, p := range []*vCore.AddUsersParams{
		{Tag: "a", Users: []panel.UserInfo{userA}},
		{Tag: "b", Users: []panel.UserInfo{userB}},
	} {
		if _, err := tt.AddUsers(p); err != nil {
			t.Fatal(err)
		}
	}
	a, err := tt.GetUserTrafficSlice("a", true)
	if err != nil || len(a) != 1 || a[0].UID != 1 {
		t.Fatalf("node a borrowed node b's UID: %v, %v", a, err)
	}
	if err := tt.DelUsers([]panel.UserInfo{userA}, "a", nil); err != nil {
		t.Fatal(err)
	}
	b, err := tt.GetUserTrafficSlice("b", true)
	if err != nil || len(b) != 1 || b[0].UID != 2 || b[0].Upload != 123 || b[0].Download != 456 {
		t.Fatalf("removing user on a lost traffic from b: %v, %v", b, err)
	}
	if a, err := tt.GetUserTrafficSlice("a", true); err != nil || len(a) != 0 {
		t.Fatalf("removed user still has a traffic mapping: %v, %v", a, err)
	}
}
