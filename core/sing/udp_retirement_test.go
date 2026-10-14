package sing

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The UDP sockets really move these datagrams before transport Close. The
// barriers hold the I/O goroutines just before they return to the counter,
// reproducing the scheduler window in which a socket is already closed but
// final packet accounting has not run yet.
func TestSingRetireNodeJoinsFinalUDPPacketAccounting(t *testing.T) {
	const tag = "retire-udp"
	b, infos := startSing(t, tag)
	user := panel.UserInfo{Id: 7, Uuid: "0b4d1a55-7a36-4d1c-9a37-0e0f6d3c3d11"}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: infos[tag]}); err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	defer limiter.DeleteLimiter(tag)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	pc := b.hookServer.RoutedPacketConnection(generationContext(context.Background(), b.users.nodes[tag]), bufio.NewPacketConn(server), adapter.InboundContext{
		Inbound: tag, User: user.Uuid, Source: M.ParseSocksaddr("5.5.5.5:12345"), Destination: M.SocksaddrFromNet(client.LocalAddr()),
	}, nil, nil)
	// Insert before any goroutine starts, immediately between successful live
	// limiter I/O and its counter. Blocking below the limiter would instead
	// model a cancelled read whose packet is correctly never delivered.
	counted := pc.(*trackedPacketConn).PacketConn.(*counter.PacketConnCounter)
	raw := &retirementBarrierPacketConn{PacketConn: counted.PacketConn, readBegan: make(chan struct{}), writeBegan: make(chan struct{}), closeBegan: make(chan struct{}), returnIO: make(chan struct{})}
	counted.PacketConn = raw
	var once sync.Once
	unblock := func() { once.Do(func() { close(raw.returnIO) }) }
	defer unblock()
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() {
		buffer := buf.NewPacket()
		defer buffer.Release()
		_, err := pc.ReadPacket(buffer)
		readDone <- err
	}()
	if _, err := client.WriteToUDP([]byte("up!"), server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	go func() { writeDone <- pc.WritePacket(buf.As([]byte("down")), M.SocksaddrFromNet(client.LocalAddr())) }()
	for _, began := range []chan struct{}{raw.readBegan, raw.writeBegan} {
		select {
		case <-began:
		case <-time.After(2 * time.Second):
			t.Fatal("actual UDP I/O did not reach final accounting barrier")
		}
	}
	readBack := make([]byte, 16)
	if n, _, err := client.ReadFromUDP(readBack); err != nil || string(readBack[:n]) != "down" {
		t.Fatalf("actual UDP reply = %q, %v", readBack[:n], err)
	}
	type result struct {
		traffic []panel.UserTraffic
		err     error
	}
	retired := make(chan result, 1)
	go func() { traffic, err := b.RetireNode(tag); retired <- result{traffic, err} }()
	select {
	case <-raw.closeBegan:
	case <-time.After(time.Second):
		t.Fatal("node retirement did not close UDP socket")
	}
	// A report while transport callbacks are still pending cannot consume and
	// discard the old storage. RetireNode must wait for those callbacks.
	if early, err := b.GetUserTrafficSlice(tag, true); err != nil || len(early) != 0 {
		t.Fatalf("unexpected early sample: %+v, %v", early, err)
	}
	select {
	case got := <-retired:
		t.Fatalf("retirement completed before UDP accounting: %+v", got)
	default:
	}
	unblock()
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-retired:
		if got.err != nil || len(got.traffic) != 1 || got.traffic[0].UID != 7 || got.traffic[0].Upload != 3 || got.traffic[0].Download != 4 {
			t.Fatalf("final UDP sample = %+v, %v", got.traffic, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("retirement did not finish after UDP callbacks returned")
	}
	if after, err := b.GetUserTrafficSlice(tag, true); err != nil || len(after) != 0 {
		t.Fatalf("UDP final bytes replayed: %+v, %v", after, err)
	}
}

type retirementBarrierPacketConn struct {
	N.PacketConn
	readBegan, writeBegan, closeBegan, returnIO chan struct{}
	closeOnce                                   sync.Once
}

func (c *retirementBarrierPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	close(c.readBegan)
	<-c.returnIO
	return destination, err
}
func (c *retirementBarrierPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := c.PacketConn.WritePacket(buffer, destination)
	close(c.writeBegan)
	<-c.returnIO
	return err
}
func (c *retirementBarrierPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeBegan) })
	return c.PacketConn.Close()
}
