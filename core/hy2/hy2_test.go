package hy2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
)

func selfSigned(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "node.test"},
		DNSNames:     []string{"node.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	cert, kf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cert, kf
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type hyRig struct {
	h     *Hysteria2
	infos map[string]*panel.NodeInfo
	opts  *conf.Options
}

func newHyRig(t *testing.T) *hyRig {
	t.Helper()
	limiter.Init()
	c, err := New(&conf.CoreConfig{Type: "hysteria2", Hysteria2Config: conf.NewHysteria2Config()})
	if err != nil {
		t.Fatal(err)
	}
	h := c.(*Hysteria2)
	t.Cleanup(func() { _ = h.Close() })
	cert, key := selfSigned(t)
	return &hyRig{h: h, infos: map[string]*panel.NodeInfo{}, opts: &conf.Options{
		ListenIP:   "127.0.0.1",
		CertConfig: &conf.CertConfig{CertMode: "file", CertFile: cert, KeyFile: key},
	}}
}

func (r *hyRig) addNode(t *testing.T, tag string, users ...panel.UserInfo) {
	t.Helper()
	info := r.infos[tag]
	if info == nil {
		hy := &panel.Hysteria2Node{}
		hy.ServerPort = freeTCPPort(t) // UDP; any free number will do on loopback
		info = &panel.NodeInfo{Type: "hysteria2", Hysteria2: hy, Common: &hy.CommonNode, Security: panel.Tls}
		r.infos[tag] = info
		limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	}
	if err := r.h.AddNode(tag, info, r.opts); err != nil {
		t.Fatalf("AddNode %s: %v", tag, err)
	}
	if _, err := r.h.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
}

func authOK(h *Hysteria2, tag, uuid string) bool {
	ok, _ := h.node(tag).Auth.Authenticate(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4)}, uuid, 0)
	return ok
}

// 🔴 Each node authenticates its own users. The user set was shared by every
// hysteria2 node in the process, so a user of one node could log in to any
// other - a tier they had not paid for included.
func TestHy2_NodesAuthenticateOnlyTheirOwnUsers(t *testing.T) {
	r := newHyRig(t)
	cheap := panel.UserInfo{Id: 1, Uuid: "user-of-cheap"}
	premium := panel.UserInfo{Id: 2, Uuid: "user-of-premium"}
	r.addNode(t, "cheap", cheap)
	r.addNode(t, "premium", premium)

	if authOK(r.h, "premium", cheap.Uuid) {
		t.Fatal("a user of one node authenticated on another node")
	}
	if !authOK(r.h, "cheap", cheap.Uuid) || !authOK(r.h, "premium", premium.Uuid) {
		t.Fatal("users must authenticate on their own node")
	}
}

// Removing a user from one node leaves them on the others.
func TestHy2_RemovalIsPerNode(t *testing.T) {
	r := newHyRig(t)
	u := panel.UserInfo{Id: 1, Uuid: "u1"}
	r.addNode(t, "A", u)
	r.addNode(t, "B", u)
	if err := r.h.DelUsers([]panel.UserInfo{u}, "A", r.infos["A"]); err != nil {
		t.Fatal(err)
	}
	if authOK(r.h, "A", u.Uuid) {
		t.Fatal("still authenticates on the node they were removed from")
	}
	if !authOK(r.h, "B", u.Uuid) {
		t.Fatal("removal from node A locked the user out of node B")
	}
}

// A removed user's open connection ends at its next traffic log instead of
// running on: hysteria checks users only at the handshake.
func TestHy2_RemovedUserConnectionEnds(t *testing.T) {
	r := newHyRig(t)
	u := panel.UserInfo{Id: 1, Uuid: "u1"}
	r.addNode(t, "A", u)
	hook := r.h.node("A").TrafficLogger.(*HookServer)
	if !hook.LogTraffic(u.Uuid, 10, 10) {
		t.Fatal("setup: a current user's traffic was refused")
	}
	_ = r.h.DelUsers([]panel.UserInfo{u}, "A", r.infos["A"])
	if hook.LogTraffic(u.Uuid, 10, 10) {
		t.Fatal("a removed user's connection keeps carrying traffic")
	}
}

// Traffic counted before a node reload is still reported after it. The ledger
// used to go away with the node.
func TestHy2_ReloadKeepsUnreportedTraffic(t *testing.T) {
	r := newHyRig(t)
	u := panel.UserInfo{Id: 7, Uuid: "u7"}
	r.addNode(t, "A", u)
	r.h.node("A").TrafficLogger.(*HookServer).LogTraffic(u.Uuid, 300, 700)

	if err := r.h.DelNode("A"); err != nil {
		t.Fatal(err)
	}
	// A report that lands mid-reload finds no node and must leave the bytes be.
	if got, _ := r.h.GetUserTrafficSlice("A", true); len(got) != 0 {
		t.Fatalf("report during the reload = %+v, want nothing yet", got)
	}
	r.addNode(t, "A", u)
	got, err := r.h.GetUserTrafficSlice("A", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].UID != 7 || got[0].Upload != 300 || got[0].Download != 700 {
		t.Fatalf("after the reload the report is %+v, want UID 7 with 300/700", got)
	}
}

// DelNode for a node that is not there is a no-op, not a nil-pointer panic.
func TestHy2_DelNodeUnknownTag(t *testing.T) {
	r := newHyRig(t)
	if err := r.h.DelNode("missing"); err != nil {
		t.Fatal(err)
	}
}

// A hysteria2 config file that cannot be read fails that node's start. It used
// to be logged with Fatal, which ended the whole process.
func TestHy2_BadConfigFileIsAnError(t *testing.T) {
	r := newHyRig(t)
	r.opts.Hysteria2ConfigPath = filepath.Join(t.TempDir(), "missing.yaml")
	hy := &panel.Hysteria2Node{}
	hy.ServerPort = freeTCPPort(t)
	info := &panel.NodeInfo{Type: "hysteria2", Hysteria2: hy, Common: &hy.CommonNode}
	if err := r.h.AddNode("A", info, r.opts); err == nil {
		t.Fatal("a missing config file must fail AddNode")
	}
}

// A node with a TCP masquerade server can be reloaded: the old server gives its
// ports back. It had no way to stop, so the new one's bind failed - and that
// failure was Fatal.
func TestHy2_MasqueradeSurvivesReload(t *testing.T) {
	r := newHyRig(t)
	httpPort, httpsPort := freeTCPPort(t), freeTCPPort(t)
	cfg := filepath.Join(t.TempDir(), "hy2.yaml")
	os.WriteFile(cfg, []byte(fmt.Sprintf("masquerade:\n  type: string\n  string:\n    content: hello\n  listenHTTP: 127.0.0.1:%d\n  listenHTTPS: 127.0.0.1:%d\n", httpPort, httpsPort)), 0o600)
	r.opts.Hysteria2ConfigPath = cfg
	u := panel.UserInfo{Id: 1, Uuid: "u1"}

	for i := 0; i < 3; i++ {
		r.addNode(t, "A", u)
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", httpPort))
		if err != nil {
			t.Fatalf("round %d: masquerade HTTP not answering: %v", i, err)
		}
		resp.Body.Close()
		if resp.Header.Get("Alt-Svc") == "" {
			t.Fatalf("round %d: Alt-Svc header missing", i)
		}
		if err := r.h.DelNode("A"); err != nil {
			t.Fatal(err)
		}
	}
}

// A connection that arrives while the node's limiter is gone is let through
// and logged. It used to Panic on hysteria's goroutine, ending the process.
func TestHy2_NoLimiterDoesNotPanic(t *testing.T) {
	limiter.Init()
	l := &serverLogger{Tag: "gone", logger: newHyRig(t).h.Logger}
	limiter.DeleteLimiter("gone")
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5}
	l.Connect(addr, "u1", 0)
	l.TCPRequest(addr, "u1", "example.com:443")
	l.UDPRequest(addr, "u1", 1, "example.com:443")
}
