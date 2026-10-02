package sing

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// Exercise the hook used by sing-box itself, including a connection created
// while unlimited and an active source address carried across multiple reports.
func TestRoutedConnectionUsesLiveLimitsAndActiveDeviceTracking(t *testing.T) {
	limiter.Init()
	const tag, uuid, ip = "live-hook", "u", "5.5.5.5"
	l := limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 7, Uuid: uuid}}, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	h := &HookServer{}
	b := &Sing{hookServer: h, users: &UserMap{uidMap: map[string]int{format.UserTag(tag, uuid): 7}}}
	left, right := net.Pipe()
	defer right.Close()
	conn := h.RoutedConnection(context.Background(), left, adapter.InboundContext{
		Inbound: tag, User: uuid, Source: M.ParseSocksaddr(ip + ":12345"),
		Destination: M.ParseSocksaddr("example.com:443"),
	}, nil, nil)
	defer conn.Close()
	for i := 0; i < 3; i++ {
		online, err := b.OnlineDevices(tag)
		if err != nil || len(online) != 1 || online[0].IP != ip || online[0].UID != 7 {
			t.Fatalf("active hook device missing: %v, %v", online, err)
		}
		_, _ = l.GetOnlineDevice()
		_, _ = b.GetDeviceTrafficSlice(tag, true)
	}
	l.UpdateUserLimits(tag, []panel.UserInfo{{Id: 7, Uuid: uuid, SpeedLimit: 1}})
	payload := make([]byte, 128*1024)
	written := make(chan error, 1)
	go func() { _, err := right.Write(payload); written <- err }()
	started := time.Now()
	if n, err := conn.Read(payload); err != nil || n != len(payload) {
		t.Fatalf("read = %d, %v", n, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 150*time.Millisecond {
		t.Fatalf("established hook ignored new 1 Mbit/s limit: %v", elapsed)
	}
	traffic, err := b.GetDeviceTrafficSlice(tag, true)
	if err != nil || traffic[7][ip] != int64(len(payload)) {
		t.Fatalf("live connection traffic = %v, %v", traffic, err)
	}
	_ = conn.Close()
	if online, err := b.OnlineDevices(tag); err != nil || len(online) != 0 {
		t.Fatalf("closed hook device still online: %v, %v", online, err)
	}
}
