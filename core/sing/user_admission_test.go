package sing

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// The inbound authenticated this stream before the panel removed its user,
// but routing can complete after DelUsers has closed every already tracked
// connection. It must not create a new set for an unauthorised user.
func TestRemovedUserCannotRegisterLateTCPOrUDPConnection(t *testing.T) {
	b, infos := startSing(t, "late")
	user := panel.UserInfo{Id: 7, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "late", Users: []panel.UserInfo{user}, NodeInfo: infos["late"]}); err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	limiter.AddLimiter("late", &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	defer limiter.DeleteLimiter("late")
	if err := b.DelUsers([]panel.UserInfo{user}, "late", infos["late"]); err != nil {
		t.Fatal(err)
	}
	metadata := adapter.InboundContext{
		Inbound: "late", User: user.Uuid, Source: M.ParseSocksaddr("5.5.5.5:12345"),
		Destination: M.ParseSocksaddr("example.com:443"),
	}
	left, right := net.Pipe()
	defer right.Close()
	tcp := b.hookServer.RoutedConnection(context.Background(), left, metadata, nil, nil)
	defer tcp.Close()
	_ = tcp.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := tcp.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Errorf("removed user's late TCP connection remains open: %v", err)
	}
	packet := &admissionPacketConn{}
	udp := b.hookServer.RoutedPacketConnection(context.Background(), packet, metadata, nil, nil)
	defer udp.Close()
	if !packet.closed {
		t.Error("removed user's late UDP connection remains open")
	}
	if v, found := b.hookServer.conns.Load(format.UserTag("late", user.Uuid)); found {
		uc := v.(*userConns)
		uc.mu.Lock()
		active := len(uc.m)
		uc.mu.Unlock()
		if active != 0 {
			t.Errorf("removed user has %d tracked connections", active)
		}
	}
	// A later successful panel addition authorises the user again.
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "late", Users: []panel.UserInfo{user}, NodeInfo: infos["late"]}); err != nil {
		t.Fatal(err)
	}
	if release, result := b.hookServer.register(format.UserTag("late", user.Uuid), &nopCloser{}, 0); result != registered {
		t.Fatalf("re-added user refused: %v", result)
	} else {
		release()
	}
}

// AnyTLS stream Close can wait for a FIN write. Removing one user's old set
// must not hold the admission lock for every node throughout that wait, nor
// let the eventual cleanup close a newly re-added generation of that user.
func TestSlowUserCloseDoesNotBlockOtherNodeOrCloseReaddedGeneration(t *testing.T) {
	b, infos := startSing(t, "slow-A", "active-B")
	user := []panel.UserInfo{{Id: 7, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}}
	for tag, info := range infos {
		if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: user, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
	}
	resume := make(chan struct{})
	var resumed sync.Once
	unblock := func() { resumed.Do(func() { close(resume) }) }
	defer unblock()
	old := &admissionSlowCloser{began: make(chan struct{}), resume: resume}
	if _, result := b.hookServer.register(format.UserTag("slow-A", user[0].Uuid), old, 0); result != registered {
		t.Fatal(result)
	}
	deleted := make(chan error, 1)
	go func() { deleted <- b.DelUsers(user, "slow-A", infos["slow-A"]) }()
	select {
	case <-old.began:
	case <-time.After(time.Second):
		t.Fatal("old user's connection was not closed")
	}
	other := make(chan registerResult, 1)
	go func() {
		release, result := b.hookServer.register(format.UserTag("active-B", user[0].Uuid), &nopCloser{}, 0)
		if release != nil {
			release()
		}
		other <- result
	}()
	select {
	case result := <-other:
		if result != registered {
			t.Fatalf("another node refused admission during slow close: %v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("another node's admission blocked by slow user Close")
	}
	readded := make(chan error, 1)
	go func() {
		_, err := b.AddUsers(&vCore.AddUsersParams{Tag: "slow-A", Users: user, NodeInfo: infos["slow-A"]})
		readded <- err
	}()
	select {
	case err := <-readded:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("re-adding the user blocked by old generation's Close")
	}
	fresh := &admissionRecordingCloser{}
	release, result := b.hookServer.register(format.UserTag("slow-A", user[0].Uuid), fresh, 0)
	if result != registered {
		t.Fatalf("re-added generation refused: %v", result)
	}
	defer release()
	unblock()
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("user deletion did not finish after Close was unblocked")
	}
	if fresh.closed.Load() {
		t.Fatal("old deletion closed the re-added user's fresh connection")
	}
	v, exists := b.hookServer.conns.Load(format.UserTag("slow-A", user[0].Uuid))
	if !exists {
		t.Fatal("old deletion erased the re-added user's new connection set")
	}
	uc := v.(*userConns)
	uc.mu.Lock()
	_, tracked := uc.m[fresh]
	uc.mu.Unlock()
	if !tracked {
		t.Fatal("fresh connection is no longer tracked")
	}
}

type admissionSlowCloser struct {
	began  chan struct{}
	resume <-chan struct{}
	once   sync.Once
}

func (c *admissionSlowCloser) Close() error {
	c.once.Do(func() {
		close(c.began)
		<-c.resume
	})
	return nil
}

type admissionRecordingCloser struct{ closed atomic.Bool }

func (c *admissionRecordingCloser) Close() error { c.closed.Store(true); return nil }

type admissionPacketConn struct{ closed bool }

func (c *admissionPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}
func (c *admissionPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error { return nil }
func (c *admissionPacketConn) Close() error                               { c.closed = true; return nil }
func (*admissionPacketConn) LocalAddr() net.Addr                          { return &net.UDPAddr{} }
func (*admissionPacketConn) SetDeadline(time.Time) error                  { return nil }
func (*admissionPacketConn) SetReadDeadline(time.Time) error              { return nil }
func (*admissionPacketConn) SetWriteDeadline(time.Time) error             { return nil }

func TestFailedAddUsersDoesNotPublishUIDAttribution(t *testing.T) {
	b, infos := startSing(t, "failed-add")
	invalid := panel.UserInfo{Id: 17, Uuid: ""}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "failed-add", Users: []panel.UserInfo{invalid}, NodeInfo: infos["failed-add"]}); err == nil {
		t.Fatal("empty Shadowsocks password accepted")
	}
	if _, found := b.users.uidMap[format.UserTag("failed-add", invalid.Uuid)]; found {
		t.Fatal("failed user addition published billing/admission identity")
	}
}

func TestShadowsocks2022ShortUserKeyReturnsErrorWithoutPanic(t *testing.T) {
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(cipher, func(t *testing.T) {
			b, _ := startSing(t)
			ss := &panel.ShadowsocksNode{Cipher: cipher, ServerKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
			info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
			if err := b.AddNode("ss2022", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("short panel credential panicked: %v", r)
				}
			}()
			if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "ss2022", Users: []panel.UserInfo{{Id: 7, Uuid: "short"}}, NodeInfo: info}); err == nil {
				t.Fatal("short key accepted")
			}
			if len(b.users.uidMap) != 0 {
				t.Fatal("invalid key published UID attribution")
			}
			// A rejected update must not poison the inbound's user list.
			if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "ss2022", Users: []panel.UserInfo{{Id: 8, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}}, NodeInfo: info}); err != nil {
				t.Fatalf("valid update after rejected key failed: %v", err)
			}
		})
	}
}

func TestNodePortDoesNotWrapThroughUint16(t *testing.T) {
	for _, port := range []int{-1, 65536, 70000} {
		ss := &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}
		ss.ServerPort = port
		info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
		if _, err := getInboundOptions("invalid-port", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}); err == nil {
			t.Errorf("port %d accepted after narrowing to uint16", port)
		}
	}
}
