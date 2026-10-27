package mihomo

import (
	"bytes"
	"github.com/PoriyaVali/V2bX/api/panel"
	S "github.com/metacubex/mihomo/transport/socks5"
	"io"
	"net"
	"testing"
	"time"
)

func halfcloseClient(t *testing.T, info *panel.NodeInfo, target string) *net.TCPConn {
	t.Helper()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: info.Common.ServerPort}
	c, e := net.DialTCP("tcp", nil, addr)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = S.ClientHandshake(c, S.ParseAddr(target), S.CmdConnect, &S.User{Username: subscriber.Uuid, Password: subscriber.Uuid}); e != nil {
		t.Fatal(e)
	}
	return c
}
func TestTCPRequestEOFStillReceivesResponse(t *testing.T) {
	c, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	server, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	go func() {
		conn, e := server.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		body, e := io.ReadAll(conn)
		if e == nil {
			_, _ = conn.Write(append([]byte("reply:"), body...))
		}
	}()
	client := halfcloseClient(t, info, server.Addr().String())
	if _, e = client.Write([]byte("request")); e != nil {
		t.Fatal(e)
	}
	if e = client.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	response, e := io.ReadAll(client)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(response, []byte("reply:request")) {
		t.Fatalf("response lost after request FIN: %q", response)
	}
	traffic, e := c.RetireNode(t.Name())
	if e != nil {
		t.Fatal(e)
	}
	if len(traffic) != 1 || traffic[0].Upload != 7 || traffic[0].Download != 13 {
		t.Fatal(traffic)
	}
}
func TestTCPResponseEOFStillAllowsRequestData(t *testing.T) {
	_, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	server, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, e := server.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("greeting"))
		_ = conn.(*net.TCPConn).CloseWrite()
		body, _ := io.ReadAll(conn)
		received <- body
	}()
	client := halfcloseClient(t, info, server.Addr().String())
	greeting, e := io.ReadAll(client)
	if e != nil {
		t.Fatal(e)
	}
	if string(greeting) != "greeting" {
		t.Fatal(string(greeting))
	}
	if _, e = client.Write([]byte("after response FIN")); e != nil {
		t.Fatal(e)
	}
	if e = client.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	select {
	case body := <-received:
		if string(body) != "after response FIN" {
			t.Fatalf("upload lost after response FIN: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("half-closed response blocked request")
	}
}
