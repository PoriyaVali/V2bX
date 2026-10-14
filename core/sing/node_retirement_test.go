package sing

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func TestSingDelNodeRetiresOnlyItsUsersAndTrackedStreams(t *testing.T) {
	b, infos := startSing(t, "retire-A", "retire-A|B")
	users := []panel.UserInfo{{Id: 7, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}}
	for tag, info := range infos {
		if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
	}
	old, other := &admissionRecordingCloser{}, &admissionRecordingCloser{}
	for tag, conn := range map[string]*admissionRecordingCloser{"retire-A": old, "retire-A|B": other} {
		if _, result := b.hookServer.register(format.UserTag(tag, users[0].Uuid), conn, 0, "5.5.5.5"); result != registered {
			t.Fatal(result)
		}
	}
	if devices, err := b.OnlineDevices("retire-A"); err != nil || len(devices) != 1 {
		t.Fatalf("node names with delimiter crossed online ownership: %+v, %v", devices, err)
	}
	if err := b.DelNode("retire-A"); err != nil {
		t.Fatal(err)
	}
	if !old.closed.Load() {
		t.Error("deleted node retained its established stream")
	}
	if other.closed.Load() {
		t.Error("deleting one node closed another node's stream")
	}
	b.users.mapLock.RLock()
	_, stale := b.users.uidMap[format.UserTag("retire-A", users[0].Uuid)]
	_, preserved := b.users.uidMap[format.UserTag("retire-A|B", users[0].Uuid)]
	b.users.mapLock.RUnlock()
	if stale {
		t.Error("deleted node retained user membership")
	}
	if !preserved {
		t.Error("deleting one node erased another node's user membership")
	}
	if release, result := b.hookServer.register(format.UserTag("retire-A", users[0].Uuid), &nopCloser{}, 0); result != userRemoved {
		if release != nil {
			release()
		}
		t.Errorf("late deleted-node registration = %v, want userRemoved", result)
	}
}

// Underlying Close unblocks transport I/O, but the goroutine returning from a
// successful read/write can still be about to execute its counter callback.
// That final n must remain reportable under the retired UID, even if the same
// credential is immediately re-added with a different panel UID.
func TestSingRemovedUIDKeepsConcurrentFinalReadWriteBytes(t *testing.T) {
	b, infos := startSing(t, "final-bytes")
	user := panel.UserInfo{Id: 7, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "final-bytes", Users: []panel.UserInfo{user}, NodeInfo: infos["final-bytes"]}); err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	limiter.AddLimiter("final-bytes", &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	defer limiter.DeleteLimiter("final-bytes")
	raw := &retirementBarrierConn{readBegan: make(chan struct{}), writeBegan: make(chan struct{}), closeBegan: make(chan struct{}), returnIO: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(raw.returnIO) }) }
	defer unblock()
	conn := b.hookServer.RoutedConnection(generationContext(context.Background(), b.users.nodes["final-bytes"]), raw, adapter.InboundContext{
		Inbound: "final-bytes", User: user.Uuid, Source: M.ParseSocksaddr("5.5.5.5:12345"), Destination: M.ParseSocksaddr("example.com:443"),
	}, nil, nil)
	readResult, writeResult := make(chan int, 1), make(chan int, 1)
	go func() { n, _ := conn.Read(make([]byte, 3)); readResult <- n }()
	go func() { n, _ := conn.Write([]byte("down")); writeResult <- n }()
	for _, began := range []chan struct{}{raw.readBegan, raw.writeBegan} {
		select {
		case <-began:
		case <-time.After(time.Second):
			t.Fatal("transport I/O did not begin")
		}
	}
	deleted := make(chan error, 1)
	go func() { deleted <- b.DelUsers([]panel.UserInfo{user}, "final-bytes", infos["final-bytes"]) }()
	select {
	case <-raw.closeBegan:
	case <-time.After(time.Second):
		t.Fatal("removal did not close transport")
	}
	user.Id = 9
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "final-bytes", Users: []panel.UserInfo{user}, NodeInfo: infos["final-bytes"]}); err != nil {
		t.Fatal(err)
	}
	unblock()
	if n := <-readResult; n != 3 {
		t.Fatalf("read = %d", n)
	}
	if n := <-writeResult; n != 4 {
		t.Fatalf("write = %d", n)
	}
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("removal did not finish after transport I/O completed")
	}
	traffic, err := b.GetUserTrafficSlice("final-bytes", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(traffic) != 1 || traffic[0].UID != 7 || traffic[0].Upload != 3 || traffic[0].Download != 4 {
		t.Fatalf("final in-flight bytes = %+v, want original UID7 upload3 download4", traffic)
	}
	if next, err := b.GetUserTrafficSlice("final-bytes", true); err != nil || len(next) != 0 {
		t.Fatalf("retired bytes reported twice: %+v, %v", next, err)
	}
}

type retirementBarrierConn struct {
	readBegan, writeBegan, closeBegan, returnIO chan struct{}
	closeOnce                                   sync.Once
}

func (c *retirementBarrierConn) Read(b []byte) (int, error) {
	close(c.readBegan)
	<-c.returnIO
	return copy(b, "up!"), io.EOF
}
func (c *retirementBarrierConn) Write(b []byte) (int, error) {
	close(c.writeBegan)
	<-c.returnIO
	return len(b), nil
}
func (c *retirementBarrierConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeBegan) })
	return nil
}
func (*retirementBarrierConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*retirementBarrierConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*retirementBarrierConn) SetDeadline(time.Time) error      { return nil }
func (*retirementBarrierConn) SetReadDeadline(time.Time) error  { return nil }
func (*retirementBarrierConn) SetWriteDeadline(time.Time) error { return nil }

func TestSingOldListenerGenerationCannotRegisterIntoReplacement(t *testing.T) {
	const tag = "same-tag-reload"
	b, infos := startSing(t, tag)
	user := panel.UserInfo{Id: 7, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: infos[tag]}); err != nil {
		t.Fatal(err)
	}
	oldContext := generationContext(context.Background(), b.users.nodes[tag])
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	defer limiter.DeleteLimiter(tag)
	if err := b.DelNode(tag); err != nil {
		t.Fatal(err)
	}
	if err := b.AddNode(tag, infos[tag], &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}); err != nil {
		t.Fatal(err)
	}
	user.Id = 9
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: infos[tag]}); err != nil {
		t.Fatal(err)
	}
	freshContext := generationContext(context.Background(), b.users.nodes[tag])
	metadata := adapter.InboundContext{Inbound: tag, User: user.Uuid, Source: M.ParseSocksaddr("5.5.5.5:12345"), Destination: M.ParseSocksaddr("example.com:443")}
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		accepted bool
	}{{"old", oldContext, false}, {"missing", context.Background(), false}, {"fresh", freshContext, true}} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			conn := b.hookServer.RoutedConnection(tc.ctx, left, metadata, nil, nil)
			_, tracked := conn.(*trackedConn)
			_ = conn.Close()
			if tracked != tc.accepted {
				t.Errorf("TCP accepted=%v, want %v", tracked, tc.accepted)
			}
			packet := &admissionPacketConn{}
			pc := b.hookServer.RoutedPacketConnection(tc.ctx, packet, metadata, nil, nil)
			_, tracked = pc.(*trackedPacketConn)
			_ = pc.Close()
			if tracked != tc.accepted {
				t.Errorf("UDP accepted=%v, want %v", tracked, tc.accepted)
			}
		})
	}
}

func TestSingRetiredGenerationsCompactUntilFinalReset(t *testing.T) {
	const tag, cycles = "compact-retired", 64
	b, infos := startSing(t, tag)
	user := panel.UserInfo{Id: 7, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}
	b.nodeReportMinTrafficBytes[tag] = 100_000 // final bytes must bypass this
	for i := 0; i < cycles; i++ {
		if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: infos[tag]}); err != nil {
			t.Fatal(err)
		}
		b.hookServer.trafficStorages(tag, user.Uuid, "", false)[0].UpCounter.Add(1)
		if err := b.DelUsers([]panel.UserInfo{user}, tag, infos[tag]); err != nil {
			t.Fatal(err)
		}
		if len(b.users.retired[tag]) != 1 || len(b.users.retired[tag][7].parts) != 0 {
			t.Fatalf("cycle%d retained historical storage generations: %+v", i, b.users.retired[tag])
		}
	}
	for i := 0; i < 2; i++ {
		traffic, err := b.GetUserTrafficSlice(tag, false)
		if err != nil || len(traffic) != 1 || traffic[0].UID != 7 || traffic[0].Upload != cycles {
			t.Fatalf("peek%d = %+v, %v", i, traffic, err)
		}
	}
	traffic, err := b.GetUserTrafficSlice(tag, true)
	if err != nil || len(traffic) != 1 || traffic[0].Upload != cycles {
		t.Fatalf("final subthreshold sample = %+v, %v", traffic, err)
	}
	if len(b.users.retired) != 0 {
		t.Fatalf("reset retained completed generation ledger: %+v", b.users.retired)
	}
}

// Optimised copy unwrapping must not bypass the gate, or a copy can execute its
// counter callbacks after retirement has declared the old storage complete.
func TestSingTrackedIOCannotBeUnwrappedPastCompletionBarrier(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	tcp := &trackedConn{Conn: left}
	defer tcp.Close()
	if reader, _ := N.UnwrapCountReader(tcp, nil); reader != tcp {
		t.Fatal("TCP reader bypassed gate")
	}
	if writer, _ := N.UnwrapCountWriter(tcp, nil); writer != tcp {
		t.Fatal("TCP writer bypassed gate")
	}
	packet := &trackedPacketConn{PacketConn: &admissionPacketConn{}}
	defer packet.Close()
	if reader, _ := N.UnwrapCountPacketReader(packet, nil); reader != packet {
		t.Fatal("UDP reader bypassed gate")
	}
	if writer, _ := N.UnwrapCountPacketWriter(packet, nil); writer != packet {
		t.Fatal("UDP writer bypassed gate")
	}
	// Closed buffer operations still own/release their supplied output buffer.
	_ = tcp.Close()
	if err := tcp.WriteBuffer(buf.As([]byte("closed"))); err == nil {
		t.Fatal("closed extended TCP write accepted")
	}
	_ = packet.Close()
	if err := packet.WritePacket(buf.As([]byte("closed")), M.Socksaddr{}); err == nil {
		t.Fatal("closed UDP write accepted")
	}
}

// The dependency manager deletes its lookup before invoking Close. One close
// error must remain visible, but retrying the absent generation must let the
// controller rebuild rather than getting stuck on "inbound not found" forever.
func TestSingRetireNodeCloseFailureCanBeRetried(t *testing.T) {
	b, _ := startSing(t)
	const tag = "close-failure"
	want := errors.New("injected inbound close failure")
	registry := service.FromContext[adapter.InboundRegistry](b.ctx).(*inbound.Registry)
	inbound.Register(registry, "retirement-close-failure", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Inbound, error) {
		return &retirementFailingInbound{tag: tag, err: want}, nil
	})
	if err := b.box.Inbound().Create(b.ctx, b.router, b.logFactory.NewLogger("test"), tag, "retirement-close-failure", &struct{}{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.RetireNode(tag); err == nil {
		t.Fatal("physical close failure was swallowed")
	}
	if traffic, err := b.RetireNode(tag); err != nil || len(traffic) != 0 {
		t.Fatalf("already retired generation cannot be retried: %+v, %v", traffic, err)
	}
}

type retirementFailingInbound struct {
	tag string
	err error
}

func (i *retirementFailingInbound) Tag() string                  { return i.tag }
func (*retirementFailingInbound) Type() string                   { return "retirement-close-failure" }
func (*retirementFailingInbound) Start(adapter.StartStage) error { return nil }
func (i *retirementFailingInbound) Close() error                 { return i.err }
