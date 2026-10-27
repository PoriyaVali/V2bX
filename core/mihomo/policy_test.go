package mihomo

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	C "github.com/metacubex/mihomo/constant"
)

func TestRealTransferSpeedAndLiveUpgrade(t *testing.T) {
	c, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	n, _ := c.get(t.Name())
	target := tcpEcho(t)
	n.limiter.UpdateUserLimits(t.Name(), []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, SpeedLimit: 1}})
	conn := dial(t, client(t, info, subscriber), target)
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	payload := bytes.Repeat([]byte{0x5a}, 256*1024)
	start := time.Now()
	written := make(chan error, 1)
	go func() { _, e := conn.Write(payload); written <- e }()
	out := make([]byte, len(payload))
	_, e := io.ReadFull(conn, out)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-written; e != nil {
		t.Fatal(e)
	}
	elapsed := time.Since(start)
	// Upload and download share V2bX's 1 Mbps bucket, including its 64 KiB burst.
	if elapsed < 2700*time.Millisecond || elapsed > 9*time.Second {
		t.Fatalf("1 Mbps round trip took %s", elapsed)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("limited payload corrupted")
	}
	large := bytes.Repeat([]byte{0x6b}, 1024*1024)
	done := make(chan error, 1)
	go func() {
		if _, e := conn.Write(large); e != nil {
			done <- e
			return
		}
		done <- nil
	}()
	start = time.Now()
	time.AfterFunc(150*time.Millisecond, func() {
		n.limiter.UpdateUserLimits(t.Name(), []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, SpeedLimit: 20}})
	})
	out = make([]byte, len(large))
	if _, e = io.ReadFull(conn, out); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("active connection did not receive upgraded speed")
	}
	if !bytes.Equal(out, large) {
		t.Fatal("live-upgrade payload corrupted")
	}
}

func TestNodesAndRetiredUIDsNeverShareAccounting(t *testing.T) {
	c, info, options := fixture(t, "socks5", []panel.UserInfo{subscriber})
	tag := t.Name()
	otherTag := tag + "/other"
	other := *info
	common := *info.Common
	common.ServerPort = freePort(t)
	other.Common = &common
	m := *info.Mihomo
	m.CommonNode = common
	other.Mihomo = &m
	limiter.AddLimiter(otherTag, &conf.LimitConfig{ConnLimit: 32}, []panel.UserInfo{subscriber}, nil)
	defer limiter.DeleteLimiter(otherTag)
	if e := c.AddNode(otherTag, &other, options); e != nil {
		t.Fatal(e)
	}
	if _, e := c.AddUsers(&vCore.AddUsersParams{Tag: otherTag, Users: []panel.UserInfo{subscriber}}); e != nil {
		t.Fatal(e)
	}
	dst := tcpEcho(t)
	a := dial(t, client(t, info, subscriber), dst)
	b := dial(t, client(t, &other, subscriber), dst)
	if e := roundtrip(a, []byte("first")); e != nil {
		t.Fatal(e)
	}
	if e := roundtrip(b, []byte("second-node")); e != nil {
		t.Fatal(e)
	}
	if e := c.DelUsers([]panel.UserInfo{subscriber}, tag, info); e != nil {
		t.Fatal(e)
	}
	if e := roundtrip(b, []byte("still-active")); e != nil {
		t.Fatal("other node was revoked", e)
	}
	renamed := subscriber
	renamed.Id = 99
	if _, e := c.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{renamed}}); e != nil {
		t.Fatal(e)
	}
	n, _ := c.get(tag)
	n.limiter.UpdateUser(tag, []panel.UserInfo{renamed}, []panel.UserInfo{subscriber})
	fresh := dial(t, client(t, info, renamed), dst)
	if e := roundtrip(fresh, []byte("new-uid")); e != nil {
		t.Fatal(e)
	}
	traffic, e := c.RetireNode(tag)
	if e != nil {
		t.Fatal(e)
	}
	byUID := map[int]int64{}
	for _, v := range traffic {
		byUID[v.UID] = v.Upload
	}
	if byUID[17] != 5 || byUID[99] != 7 {
		t.Fatalf("UID accounting=%v", byUID)
	}
	otherTraffic, _ := c.RetireNode(otherTag)
	if len(otherTraffic) != 1 || otherTraffic[0].Upload != 23 {
		t.Fatal(otherTraffic)
	}
}

func TestDestinationPolicyPinsCheckedIP(t *testing.T) {
	c, _, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	n, _ := c.get(t.Name())
	n.config.AllowPrivateDestinations = false
	for _, host := range []string{"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1"} {
		m := metadata(t, net.JoinHostPort(host, "80"))
		if _, e := n.destination(context.Background(), m); e == nil {
			t.Fatalf("private/reserved address accepted: %s", host)
		}
	}
	if _, e := n.destination(context.Background(), &C.Metadata{DstIP: netip.MustParseAddr("198.51.100.1"), DstPort: 443}); e != nil {
		t.Fatal(e)
	}
}

func TestRejectedReplacementKeepsExistingListener(t *testing.T) {
	c, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	tag := t.Name()
	target := tcpEcho(t)
	active := dial(t, client(t, info, subscriber), target)
	if _, e := c.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{{Id: 18, Uuid: subscriber.Uuid}}}); e == nil {
		t.Fatal("duplicate identity accepted")
	}
	if e := roundtrip(active, []byte("unchanged")); e != nil {
		t.Fatal(e)
	}
}

func TestTLSAndTransportVariants(t *testing.T) {
	for _, variant := range []struct {
		protocol, network string
		tls               bool
	}{
		{"http", "", true}, {"socks5", "", true}, {"vmess", "", true}, {"vless", "", true}, {"mieru", "UDP", false},
	} {
		t.Run(variant.protocol+variant.network, func(t *testing.T) {
			c, info, _ := fixture(t, variant.protocol, nil)
			if variant.tls {
				info.Security = panel.Tls
				if info.Mihomo != nil {
					info.Mihomo.TLS = true
				}
			}
			if variant.protocol == "mieru" {
				info.Mihomo.Transport = variant.network
			}
			if _, e := c.AddUsers(&vCore.AddUsersParams{Tag: t.Name(), Users: []panel.UserInfo{subscriber}}); e != nil {
				t.Fatal(e)
			}
			n, _ := c.get(t.Name())
			n.limiter.UpdateUser(t.Name(), []panel.UserInfo{subscriber}, nil)
			conn := dial(t, client(t, info, subscriber), tcpEcho(t))
			if e := roundtrip(conn, []byte("variant")); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestDestinationRulesBlockRealTCP(t *testing.T) {
	c, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	n, _ := c.get(t.Name())
	target := tcpEcho(t)
	_, port, _ := net.SplitHostPort(target)
	if e := n.limiter.UpdateRule(&panel.Rules{Port: []string{port}}); e != nil {
		t.Fatal(e)
	}
	p := client(t, info, subscriber)
	conn := dial(t, p, target)
	if e := roundtrip(conn, []byte("blocked port")); e == nil {
		t.Fatal("blocked port forwarded")
	}
	if e := n.limiter.UpdateRule(&panel.Rules{}); e != nil {
		t.Fatal(e)
	}
	conn = dial(t, p, target)
	if e := roundtrip(conn, []byte("allowed again")); e != nil {
		t.Fatal(e)
	}
}
