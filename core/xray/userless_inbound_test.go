package xray

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

// An operator's own inbound (InboundConfigPath) has no V2bX users. xray's
// socks, http and dokodemo inbounds hand DispatchLink a plain reader, and with
// sniffing on the dispatcher used it as a buf.TimeoutReader without wrapping
// it first - a type assertion that panicked and took the whole process down on
// the first connection. Upstream wraps every link; this checks ours does too.
func TestXray_UserlessSniffingInboundCarriesTraffic(t *testing.T) {
	echo := echoServer(t)
	port := freePort(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "inbound.json")
	os.WriteFile(in, []byte(`[{"tag":"local-socks","listen":"127.0.0.1","port":`+strconv.Itoa(port)+
		`,"protocol":"socks","settings":{"auth":"noauth"},"sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":true}}]`), 0o600)
	out := filepath.Join(dir, "outbound.json")
	os.WriteFile(out, []byte(`[{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]`), 0o600)

	xc := conf.NewXrayConfig()
	xc.InboundConfigPath = in
	xc.OutboundConfigPath = out
	c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: xc})
	if err != nil {
		t.Fatal(err)
	}
	x := c.(*Xray)
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	host, ps, _ := net.SplitHostPort(echo)
	p, _ := strconv.Atoi(ps)
	conn.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	conn.Write(append(append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...), byte(p>>8), byte(p)))
	head := make([]byte, 10)
	if _, err := io.ReadFull(conn, head); err != nil || head[1] != 0 {
		t.Fatalf("socks connect: %v %v", err, head)
	}
	msg := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	conn.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != string(msg) {
		t.Fatalf("echo through the custom inbound: %q, %v", got, err)
	}
}

// xray's own components dispatch with no inbound in the context at all - a
// DNS query sent over TCP or DoH outside any connection, a reverse bridge. The
// dispatcher read sessionInbound.User without checking sessionInbound, a nil
// dereference in the routing goroutine that killed the process.
func TestXray_DispatchWithoutInboundDoesNotPanic(t *testing.T) {
	echo := echoServer(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "outbound.json")
	os.WriteFile(out, []byte(`[{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]`), 0o600)
	xc := conf.NewXrayConfig()
	xc.OutboundConfigPath = out
	c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: xc})
	if err != nil {
		t.Fatal(err)
	}
	x := c.(*Xray)
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })

	d := x.Server.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	dest, err := xnet.ParseDestination("tcp:" + echo)
	if err != nil {
		t.Fatal(err)
	}
	link, err := d.Dispatch(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	payload := buf.New()
	payload.WriteString("ping")
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	mb, err := link.Reader.(buf.TimeoutReader).ReadMultiBufferTimeout(5 * time.Second)
	if err != nil || mb.String() != "ping" {
		t.Fatalf("echo through an inbound-less dispatch: %q, %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	common.Close(link.Writer)
}
