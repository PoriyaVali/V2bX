package panel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/vmihailenco/msgpack/v5"
)

// A damaged response must not revoke users or be cached as an applied list.
func TestGetUserListRejectsInvalidEnvelope(t *testing.T) {
	for name, body := range map[string]string{
		"missing object close":      `{"users":[]`,
		"malformed trailing member": `{"users":[],"metadata":`,
		"trailing garbage":          `{"users":[]} garbage`,
		"second JSON value":         `{"users":[]} {"users":[]}`,
		"duplicate users":           `{"users":[],"users":[{"id":7,"uuid":"eligible"}]}`,
		"nested users only":         `{"metadata":{"users":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("ETag", `"same-version"`)
				if calls == 1 {
					fmt.Fprint(w, body)
					return
				}
				if r.Header.Get("If-None-Match") != "" {
					t.Error("invalid response was remembered in the conditional request")
					w.WriteHeader(http.StatusNotModified)
					return
				}
				fmt.Fprint(w, `{"users":[{"id":7,"uuid":"eligible"}]}`)
			}))
			defer srv.Close()
			client, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "test", NodeType: "anytls", Timeout: 5})
			if err != nil {
				t.Fatal(err)
			}
			if users, err := client.GetUserList(); err == nil {
				t.Errorf("invalid envelope accepted as %d users", len(users))
			}
			users, err := client.GetUserList()
			if err != nil || len(users) != 1 || users[0].Uuid != "eligible" {
				t.Fatalf("corrected list not applied: users=%+v err=%v", users, err)
			}
		})
	}
}

func TestGetUserListMsgpackValidatesEnvelope(t *testing.T) {
	pack := func(value any) []byte {
		t.Helper()
		body, err := msgpack.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	valid := pack(map[string]any{"users": []UserInfo{{Id: 7, Uuid: "eligible"}}})
	empty := pack(map[string]any{"users": []UserInfo{}})
	duplicate := []byte{0x82}
	duplicate = append(duplicate, pack("users")...)
	duplicate = append(duplicate, pack([]UserInfo{})...)
	duplicate = append(duplicate, pack("users")...)
	duplicate = append(duplicate, pack([]UserInfo{{Id: 7, Uuid: "eligible"}})...)
	for name, body := range map[string][]byte{
		"missing users":     pack(map[string]any{"metadata": "ok"}),
		"null users":        pack(map[string]any{"users": nil}),
		"nested users only": pack(map[string]any{"metadata": map[string]any{"users": []UserInfo{}}}),
		"trailing garbage":  append(append([]byte{}, empty...), 0xc1),
		"second value":      append(append([]byte{}, empty...), valid...),
		"duplicate users":   duplicate,
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/x-msgpack")
				w.Header().Set("ETag", `"same-version"`)
				if calls == 1 {
					_, _ = w.Write(body)
					return
				}
				if r.Header.Get("If-None-Match") != "" {
					t.Error("invalid MessagePack envelope was cached")
				}
				_, _ = w.Write(valid)
			}))
			defer srv.Close()
			client, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "test", NodeType: "anytls", Timeout: 5})
			if err != nil {
				t.Fatal(err)
			}
			if users, err := client.GetUserList(); err == nil {
				t.Errorf("invalid MessagePack accepted as %d users", len(users))
			}
			users, err := client.GetUserList()
			if err != nil || len(users) != 1 || users[0].Uuid != "eligible" {
				t.Fatalf("corrected MessagePack list not applied: users=%+v err=%v", users, err)
			}
		})
	}
	for name, body := range map[string][]byte{"eligible": valid, "empty": empty} {
		t.Run("valid/"+name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/x-msgpack")
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			client, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "test", NodeType: "anytls", Timeout: 5})
			if err != nil {
				t.Fatal(err)
			}
			users, err := client.GetUserList()
			want := 0
			if name == "eligible" {
				want = 1
			}
			if err != nil || len(users) != want {
				t.Fatalf("valid MessagePack rejected: users=%+v err=%v", users, err)
			}
		})
	}
}

func TestGetUserListUsesOnlyTopLevelUsers(t *testing.T) {
	for name, body := range map[string]string{
		"nested member": `{"metadata":{"users":[]},"users":[{"id":7,"uuid":"eligible"}],"after":{"users":[]}}`,
		"string value":  `{"message":"users","users":[{"id":7,"uuid":"eligible"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, body)
			}))
			defer srv.Close()
			client, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "test", NodeType: "anytls", Timeout: 5})
			if err != nil {
				t.Fatal(err)
			}
			users, err := client.GetUserList()
			if err != nil || len(users) != 1 || users[0].Uuid != "eligible" {
				t.Fatalf("top-level list obscured by metadata: users=%+v err=%v", users, err)
			}
		})
	}
}
