package panel

import (
	"crypto/sha1"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
)

func TestIntervalToTime(t *testing.T) {
	cases := []struct {
		in   interface{}
		want time.Duration
	}{
		{nil, defaultInterval}, // used to panic
		{0, defaultInterval},   // used to become a busy loop
		{-5, defaultInterval},
		{"", defaultInterval},
		{"abc", defaultInterval},
		{"41", 41 * time.Second},
		{float64(31), 31 * time.Second},
		{60, 60 * time.Second},
	}
	for _, c := range cases {
		if got := intervalToTime(c.in); got != c.want {
			t.Errorf("intervalToTime(%#v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestRouteMatches(t *testing.T) {
	cases := []struct {
		in   interface{}
		want []string
	}{
		{nil, nil},
		{"", nil},
		{[]interface{}{}, nil},
		{"a.com, b.com,,", []string{"a.com", "b.com"}},
		{[]string{"x", " "}, []string{"x"}},
		{[]interface{}{"x", 3.0, nil, "y"}, []string{"x", "y"}},
		{map[string]interface{}{"a": 1}, nil},
	}
	for _, c := range cases {
		got := routeMatches(c.in)
		if len(got) != len(c.want) {
			t.Errorf("routeMatches(%#v) = %q, want %q", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("routeMatches(%#v) = %q, want %q", c.in, got, c.want)
			}
		}
	}
}

// Routes the panel may legitimately send in odd shapes must not crash the
// node; they used to hit an unchecked type assertion or matchs[0] on empty.
func TestGetNodeInfo_OddRoutesDoNotCrash(t *testing.T) {
	body := `{"server_port":1234,"cipher":"aes-128-gcm",
	  "base_config":{"push_interval":0,"pull_interval":null},
	  "routes":[
	    {"id":1,"match":null,"action":"block"},
	    {"id":2,"match":[],"action":"dns","action_value":"1.1.1.1"},
	    {"id":3,"match":[1,"*.bad.example"],"action":"block"},
	    {"id":4,"match":"protocol:bittorrent","action":"block"}
	  ]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	defer srv.Close()
	c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "k", NodeType: "shadowsocks", Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if len(n.Rules.Regexp) != 1 || n.Rules.Regexp[0] != "*.bad.example" {
		t.Fatalf("domain rules = %q", n.Rules.Regexp)
	}
	if len(n.Rules.Protocol) != 1 || n.Rules.Protocol[0] != "bittorrent" {
		t.Fatalf("protocol rules = %q", n.Rules.Protocol)
	}
	if n.PushInterval != defaultInterval || n.PullInterval != defaultInterval {
		t.Fatalf("intervals = %s / %s, want the default", n.PushInterval, n.PullInterval)
	}
}

// A config the node could not decode must not be remembered as applied: once
// the panel serves it correctly, the node has to pick it up.
func TestGetNodeInfo_UndecodableReplyIsNotRemembered(t *testing.T) {
	good := `{"server_port":1234,"cipher":"aes-128-gcm","base_config":{"push_interval":60,"pull_interval":60}}`
	var bodies = []string{`{"server_port":"not a number"`, good}
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := bodies[len(bodies)-1]
		if calls < len(bodies) {
			b = bodies[calls]
		}
		calls++
		etag := fmt.Sprintf(`"%x"`, sha1.Sum([]byte(b)))
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(b))
	}))
	defer srv.Close()
	c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "k", NodeType: "shadowsocks", Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetNodeInfo(); err == nil {
		t.Fatal("a broken config decoded without error")
	}
	n, err := c.GetNodeInfo()
	if err != nil || n == nil {
		t.Fatalf("the good config after a broken one was not applied: node=%v err=%v", n, err)
	}
}

// A panel that omits base_config must get the default intervals, not a nil
// pointer panic - on a node's first start nothing recovers from that panic,
// so it took down every node the process served.
func TestGetNodeInfo_MissingBaseConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"server_port":1234,"cipher":"aes-128-gcm"}`))
	}))
	defer srv.Close()
	c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "k", NodeType: "shadowsocks", Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	node, err := c.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.PushInterval != defaultInterval || node.PullInterval != defaultInterval {
		t.Fatalf("intervals = %s/%s, want the default %s", node.PushInterval, node.PullInterval, defaultInterval)
	}
	if node.NodeReportMinTraffic != 0 || node.DeviceOnlineMinTraffic != 0 {
		t.Fatalf("thresholds must stay off without base_config, got %d/%d",
			node.NodeReportMinTraffic, node.DeviceOnlineMinTraffic)
	}
}
