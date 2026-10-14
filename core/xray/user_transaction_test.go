package xray

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func TestAddUsersMissingInboundDoesNotCreateUIDMapping(t *testing.T) {
	x, _, _ := xrayNode(t, 0)
	const tag = "missing-inbound"
	ss := &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
	added, err := x.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{{Id: 99, Uuid: e2eUUID}},
		NodeInfo: &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss}})
	if err == nil || added != 0 {
		t.Fatalf("user accepted on absent inbound: added=%d error=%v", added, err)
	}
	if got, ok := x.users.uidMap[format.UserTag(tag, e2eUUID)]; ok {
		t.Fatalf("rejected user created a traffic UID mapping: %d", got)
	}
}

func TestShadowsocks2022ValidCredentialDerivationIsPreserved(t *testing.T) {
	for _, tc := range []struct {
		cipher string
		bytes  int
	}{{"2022-blake3-aes-128-gcm", 16}, {"2022-blake3-aes-256-gcm", 32}} {
		users, err := buildSSUsers("valid", []panel.UserInfo{{Id: 1, Uuid: e2eUUID}}, tc.cipher, "server-key")
		if err != nil || len(users) != 1 {
			t.Fatalf("%s: build users: %v", tc.cipher, err)
		}
		memory, err := users[0].ToMemoryUser()
		if err != nil {
			t.Fatal(err)
		}
		want := base64.StdEncoding.EncodeToString([]byte(e2eUUID[:tc.bytes]))
		if got := memory.Account.(*shadowsocks_2022.MemoryAccount).Key; got != want {
			t.Errorf("%s changed the subscriber's existing credential", tc.cipher)
		}
	}
}

func TestAddUsersShortShadowsocks2022CredentialReturnsError(t *testing.T) {
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(cipher, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("malformed panel credential panicked instead of returning an error: %v", p)
				}
			}()
			x := &Xray{users: &UserMap{uidMap: make(map[string]int)}}
			ss := &panel.ShadowsocksNode{Cipher: cipher, ServerKey: "non-empty"}
			added, err := x.AddUsers(&vCore.AddUsersParams{Tag: "short", Users: []panel.UserInfo{{Id: 10, Uuid: "short"}},
				NodeInfo: &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss}})
			if err == nil || added != 0 || !strings.Contains(err.Error(), "credential") {
				t.Fatalf("short credential: added=%d error=%v", added, err)
			}
			if len(x.users.uidMap) != 0 {
				t.Fatal("rejected credential created a traffic UID mapping")
			}
		})
	}
}
