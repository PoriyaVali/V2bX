package sing

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
)

// Real SS2022 handshakes must read one complete user table while unrelated
// users are added and removed, without races or interrupting the active user.
func TestSS2022UserChangesWithRealEncryptedHandshakes(t *testing.T) {
	sc := conf.NewSingConfig()
	sc.AllowPrivateDestinations = true
	sc.LogConfig.Disabled = true
	c, err := New(&conf.CoreConfig{Type: "sing", SingConfig: sc})
	if err != nil {
		t.Fatal(err)
	}
	b := c.(*Sing)
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	ipSK := base64.StdEncoding.EncodeToString([]byte("server-key-16byt"))
	ss := &panel.ShadowsocksNode{Cipher: "2022-blake3-aes-128-gcm", ServerKey: ipSK}
	ss.ServerPort = port
	info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: ss, Common: &ss.CommonNode}
	so := conf.NewSingOptions()
	so.ProxyProtocol = false
	if err := b.AddNode("ss22-audit", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: so}); err != nil {
		t.Fatal(err)
	}
	target := panel.UserInfo{Id: 7, Uuid: "3b1f6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10"}
	if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "ss22-audit", Users: []panel.UserInfo{target}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	limiter.AddLimiter("ss22-audit", &conf.LimitConfig{}, []panel.UserInfo{target}, nil)
	defer limiter.DeleteLimiter("ss22-audit")
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	uPSK := base64.StdEncoding.EncodeToString([]byte(target.Uuid[:16]))
	m, err := shadowaead_2022.NewWithPassword(ss.Cipher, ipSK+":"+uPSK, nil)
	if err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var echoed atomic.Int64
	var packets atomic.Int64
	var wg sync.WaitGroup
	defer func() {
		stop.Store(true)
		wg.Wait()
	}()
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, source, err := udpEcho.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteTo(buffer[:n], source)
		}
	}()
	udpRaw, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	udp := m.DialPacketConn(udpRaw)
	defer udp.Close()
	udpPayload := []byte("same encrypted UDP session survives user updates")
	roundtrip := func() error {
		_ = udp.SetDeadline(time.Now().Add(time.Second))
		if _, err := udp.WriteTo(udpPayload, udpEcho.LocalAddr()); err != nil {
			return err
		}
		response := make([]byte, 2048) // includes space for encrypted SS2022 headers
		n, _, err := udp.ReadFrom(response)
		if err == nil && !bytes.Equal(response[:n], udpPayload) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if err := roundtrip(); err != nil {
		t.Fatalf("initial SS2022 UDP echo: %v", err)
	}
	packetErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if err := roundtrip(); err != nil {
				packetErr <- err
				return
			}
			packets.Add(1)
		}
	}()
	for worker := 0; worker < 2; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
				if err != nil {
					continue
				}
				conn := m.DialEarlyConn(raw, M.ParseSocksaddr(echo.Addr().String()))
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write([]byte("valid encrypted SS2022")); err == nil {
					if _, err := io.ReadFull(conn, make([]byte, len("valid encrypted SS2022"))); err == nil {
						echoed.Add(1)
					}
				}
				_ = conn.Close()
			}
		}()
	}
	churn := panel.UserInfo{Id: 8, Uuid: "b99c6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10"}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := b.AddUsers(&vCore.AddUsersParams{Tag: "ss22-audit", Users: []panel.UserInfo{churn}, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
		if err := b.DelUsers([]panel.UserInfo{churn}, "ss22-audit", info); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	select {
	case err := <-packetErr:
		t.Fatalf("existing SS2022 UDP session interrupted by user reload: %v", err)
	default:
	}
	if err := roundtrip(); err != nil {
		t.Fatalf("final SS2022 UDP echo: %v", err)
	}
	if echoed.Load() == 0 {
		t.Fatal("no valid protocol connection completed")
	}
	if packets.Load() == 0 {
		t.Fatal("no encrypted UDP exchanges completed during reload")
	}
	t.Logf("completed %d encrypted TCP echo connections and %d exchanges on one persistent UDP session", echoed.Load(), packets.Load())
}
