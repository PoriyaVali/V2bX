package panel

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/common/serverstatus"
	"github.com/PoriyaVali/V2bX/conf"
	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

func TestReportsRequireIrboardAcknowledgement(t *testing.T) {
	for _, body := range []string{`{"data":true}`, `{"data":false}`, `{}`, `null`, `<html>login</html>`, `{"data":true} garbage`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
			defer srv.Close()
			c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: "mdns", Key: "test"})
			if err != nil {
				t.Fatal(err)
			}
			for name, report := range map[string]func() error{
				"traffic": func() error { return c.ReportUserTrafficWithID("report-123", []UserTraffic{{UID: 7, Upload: 3}}) },
				"online":  func() error { data := map[int][]string{7: {"192.0.2.1"}}; return c.ReportNodeOnlineUsers(&data) },
				"status":  func() error { return c.ReportNodeStatus(&serverstatus.SystemStatus{}) },
			} {
				err := report()
				if (err == nil) != (body == `{"data":true}`) {
					t.Errorf("%s: err=%v for %s", name, err, body)
				}
			}
		})
	}
}

func TestTrafficReportAggregatesUIDWithoutChangingWireFormat(t *testing.T) {
	var got map[int][2]int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(ReportIDHeader) != "stable-report-id" {
			t.Error("report id changed")
		}
		if err := json.UnmarshalRead(r.Body, &got); err != nil {
			t.Error(err)
		}
		fmt.Fprint(w, `{"data":true}`)
	}))
	defer srv.Close()
	c, _ := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: "mdns", Key: "test"})
	if err := c.ReportUserTrafficWithID("stable-report-id", []UserTraffic{{7, 100, 200}, {7, 5, 9}, {8, 11, 13}}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[7] != [2]int64{105, 209} || got[8] != [2]int64{11, 13} {
		t.Fatalf("traffic lost or wire format changed: %v", got)
	}
}

func TestAliveListRejectsInvalidSnapshotAndKeepsPrevious(t *testing.T) {
	for _, invalid := range []string{`{}`, `{"alive":null}`, `{"alive":{"7":-1}}`, `{"alive":{"0":1}}`, `null`} {
		t.Run(invalid, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				if calls == 1 {
					fmt.Fprint(w, `{"alive":{"7":2}}`)
				} else {
					fmt.Fprint(w, invalid)
				}
			}))
			defer srv.Close()
			c, _ := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: "mdns", Key: "test"})
			if _, err := c.GetUserAlive(); err != nil {
				t.Fatal(err)
			}
			if _, err := c.GetUserAlive(); err == nil {
				t.Fatal("invalid alive snapshot was accepted")
			}
			if c.AliveMap.Alive[7] != 2 {
				t.Fatal("previous device count was erased")
			}
		})
	}
}

func TestStreamedUserListHonorsResponseBudget(t *testing.T) {
	for _, format := range []string{"application/json", "application/x-msgpack"} {
		t.Run(format, func(t *testing.T) {
			body := []byte(`{"users":[],"padding":"` + strings.Repeat("x", 1024) + `"}`)
			if strings.Contains(format, "msgpack") {
				body, _ = msgpack.Marshal(map[string]any{"users": []UserInfo{}, "padding": strings.Repeat("x", 1024)})
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", format)
				w.Header().Set("ETag", `"too-big"`)
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			c, _ := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: "mdns", Key: "test"})
			c.client.SetResponseBodyLimit(128)
			if _, err := c.GetUserList(); err == nil {
				t.Fatal("oversized streamed reply was accepted")
			}
			if c.userEtag != "" {
				t.Fatal("oversized response was cached")
			}
		})
	}
}

func TestTruncatedMsgpackHeaderDoesNotAllocateClaimedUserCount(t *testing.T) {
	// A tiny response claiming 1,000,000 users, with no records. The generic
	// decoder used to allocate roughly 40 MB before noticing the truncation.
	body := []byte{0x81, 0xa5, 'u', 's', 'e', 'r', 's', 0xdd, 0, 0x0f, 0x42, 0x40}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := decodeMsgpackUserList(msgpack.NewDecoder(bytes.NewReader(body)), &UserListBody{})
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("truncated user list was accepted")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4<<20 {
		t.Fatalf("allocated %d bytes from a 12-byte declaration", allocated)
	}
}

func TestNilPanelResponseIsAnError(t *testing.T) {
	c := &Client{APIHost: "https://panel.example"}
	if err := c.checkResponse(nil, "/api/v1/server/UniProxy/push", nil); err == nil {
		t.Fatal("nil response was accepted")
	}
	if got := c.assembleURL("/api/v1/server/UniProxy/push"); got != "https://panel.example/api/v1/server/UniProxy/push" {
		t.Fatalf("bad URL: %s", got)
	}
}

func TestInvalidUserIdentityIsNotCached(t *testing.T) {
	for _, user := range []UserInfo{{Id: 0, Uuid: "u"}, {Id: -1, Uuid: "u"}, {Id: 1, Uuid: " "}} {
		for _, format := range []string{"json", "msgpack"} {
			t.Run(fmt.Sprintf("%+v/%s", user, format), func(t *testing.T) {
				body, _ := json.Marshal(UserListBody{Users: []UserInfo{user}})
				contentType := "application/json"
				if format == "msgpack" {
					body, _ = msgpack.Marshal(UserListBody{Users: []UserInfo{user}})
					contentType = "application/x-msgpack"
				}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", contentType)
					w.Header().Set("ETag", `"invalid-identity"`)
					_, _ = w.Write(body)
				}))
				defer srv.Close()
				c, _ := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: "mdns", Key: "test"})
				c.userEtag = `"previous"`
				if _, err := c.GetUserList(); err == nil {
					t.Fatal("invalid user identity accepted")
				}
				if c.userEtag != `"previous"` {
					t.Fatal("invalid list advanced the ETag")
				}
			})
		}
	}
}

func TestTransportErrorsAndRetryLogsRedactPanelToken(t *testing.T) {
	const token = "fictional-secret/with?query=&characters"
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	var output bytes.Buffer
	previous := log.StandardLogger().Out
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, NodeType: "mdns", Key: token, Timeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	c.client.SetRetryCount(0)
	_, err = c.GetNodeInfo()
	if err == nil {
		t.Fatal("closed endpoint accepted")
	}
	for _, value := range []string{err.Error(), output.String()} {
		if strings.Contains(value, token) || strings.Contains(value, url.QueryEscape(token)) {
			t.Fatal("API token leaked into transport diagnostics")
		}
	}
}
