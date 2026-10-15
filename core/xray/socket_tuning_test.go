package xray

import (
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet"
)

func socketSettings(t *testing.T, network string, xo *conf.XrayOptions) *internet.SocketConfig {
	t.Helper()
	v := &panel.VAllssNode{Network: network}
	if network != "tcp" {
		v.NetworkSettings = json.RawMessage(`{}`)
	}
	v.ServerPort = 1234
	info := &panel.NodeInfo{Type: "vless", VAllss: v, Common: &v.CommonNode}
	in, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", XrayOptions: xo}, info, "t")
	if err != nil {
		t.Fatalf("%s: %v", network, err)
	}
	rs, err := in.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	return rs.(*proxyman.ReceiverConfig).GetStreamSettings().GetSocketSettings()
}

// EnableTFO was applied only to transports other than tcp and ws, and keepalive
// never at all - xray listens with it off unless told. Every transport must
// carry both.
func TestBuildInbound_SocketOptionsOnEveryTransport(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"} {
		xo := conf.NewXrayOptions()
		so := socketSettings(t, network, xo)
		if so.GetTfo() != 0 {
			t.Errorf("%s: TFO %d with EnableTFO off, want the system default", network, so.GetTfo())
		}
		if so.GetTcpKeepAliveIdle() != conf.DefaultTCPKeepAliveIdle || so.GetTcpKeepAliveInterval() != conf.DefaultTCPKeepAliveInterval {
			t.Errorf("%s: keepalive %d/%d, want %d/%d", network, so.GetTcpKeepAliveIdle(), so.GetTcpKeepAliveInterval(),
				conf.DefaultTCPKeepAliveIdle, conf.DefaultTCPKeepAliveInterval)
		}

		xo.EnableTFO = true
		xo.TCPKeepAliveIdle, xo.TCPKeepAliveInterval = 300, 30
		so = socketSettings(t, network, xo)
		if so.GetTfo() <= 0 {
			t.Errorf("%s: EnableTFO did not reach the listener (tfo=%d)", network, so.GetTfo())
		}
		if so.GetTcpKeepAliveIdle() != 300 || so.GetTcpKeepAliveInterval() != 30 {
			t.Errorf("%s: keepalive %d/%d, want 300/30", network, so.GetTcpKeepAliveIdle(), so.GetTcpKeepAliveInterval())
		}

		// One negative value turns keepalive off. Both must then be negative:
		// xray refuses to listen on a mixed pair.
		xo.TCPKeepAliveIdle, xo.TCPKeepAliveInterval = -1, 0
		so = socketSettings(t, network, xo)
		if so.GetTcpKeepAliveIdle() >= 0 || so.GetTcpKeepAliveInterval() >= 0 {
			t.Errorf("%s: keepalive %d/%d, want both negative (off)", network, so.GetTcpKeepAliveIdle(), so.GetTcpKeepAliveInterval())
		}
	}
}

// A client whose first bytes arrive late - a lossy, high-latency path where
// the handshake needs retransmissions - must still be served. The node used to
// close it after 4 s.
func TestXray_SlowHandshakeIsServed(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the old handshake limit")
	}
	_, _, port := xrayNode(t, 0)
	target := echoServer(t)
	m, err := shadowaead.New("aes-128-gcm", nil, e2eUUID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	time.Sleep(5 * time.Second) // past xray's default 4 s, inside V2bX's 10 s
	conn := m.DialEarlyConn(raw, M.ParseSocksaddr(target))
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write after a slow start: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("a client that took 5 s to start was dropped: %q, %v", buf, err)
	}
}
