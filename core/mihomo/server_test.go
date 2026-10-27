package mihomo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
)

var subscriber = panel.UserInfo{Id: 17, Uuid: "00c68113-03c2-42cb-9f3c-976fe2b0eb94"}

func certificate(t *testing.T) *conf.CertConfig {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); e != nil {
		t.Fatal(e)
	}
	return &conf.CertConfig{CertMode: "file", CertFile: certPath, KeyFile: keyPath}
}
func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func fixture(t *testing.T, protocol string, users []panel.UserInfo) (*Core, *panel.NodeInfo, *conf.Options) {
	t.Helper()
	c0, e := New(&conf.CoreConfig{MihomoConfig: &conf.MihomoConfig{AllowPrivateDestinations: true, DialTimeout: 3, UDPTimeout: 2}})
	if e != nil {
		t.Fatal(e)
	}
	c := c0.(*Core)
	tag := t.Name()
	limiter.AddLimiter(tag, &conf.LimitConfig{ConnLimit: 64}, users, map[int]int{})
	t.Cleanup(func() { _ = c.Close(); limiter.DeleteLimiter(tag) })
	common := panel.CommonNode{ServerPort: freePort(t)}
	info := &panel.NodeInfo{Type: protocol, Common: &common}
	options := &conf.Options{ListenIP: "127.0.0.1", CertConfig: certificate(t), MihomoOptions: &conf.MihomoOptions{}}
	options.MihomoOptions.JLSUpstream.Addr = "127.0.0.1:9"
	options.MihomoOptions.JLSUpstream.SNI = "localhost"
	switch protocol {
	case "http", "socks5", "mieru", "shadowquic":
		info.Mihomo = &panel.MihomoNode{CommonNode: common, Transport: "TCP"}
	case "vmess", "vless":
		info.VAllss = &panel.VAllssNode{CommonNode: common}
	case "trojan":
		info.Trojan = &panel.TrojanNode{CommonNode: common}
		info.Security = panel.Tls
	case "tuic":
		info.Tuic = &panel.TuicNode{CommonNode: common, CongestionControl: "cubic"}
		info.Security = panel.Tls
	case "hysteria2":
		info.Hysteria2 = &panel.Hysteria2Node{CommonNode: common}
		info.Security = panel.Tls
	case "anytls":
		info.AnyTls = &panel.AnyTlsNode{CommonNode: common}
		info.Security = panel.Tls
	case "trusttunnel":
		info.TrustTunnel = &panel.TrustTunnelNode{CommonNode: common}
		info.Security = panel.Tls
	}
	if e = c.AddNode(tag, info, options); e != nil {
		t.Fatal(e)
	}
	if len(users) > 0 {
		if _, e = c.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); e != nil {
			t.Fatal(e)
		}
	}
	return c, info, options
}
func client(t *testing.T, info *panel.NodeInfo, u panel.UserInfo, overrides ...map[string]any) C.Proxy {
	t.Helper()
	options := map[string]any{"name": "test", "type": info.Type, "server": "127.0.0.1", "port": info.Common.ServerPort, "username": u.Uuid, "password": u.Uuid, "uuid": u.Uuid, "udp": true, "skip-cert-verify": true, "sni": "localhost", "servername": "localhost", "cipher": "auto", "alterId": 0, "version": 5, "congestion-controller": "cubic"}
	if info.Type == "mieru" {
		options["transport"] = info.Mihomo.Transport
	}
	if info.Security == panel.Tls {
		options["tls"] = true
	}
	for _, extra := range overrides {
		for k, v := range extra {
			options[k] = v
		}
	}
	p, e := adapter.ParseProxy(options)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
func tcpEcho(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}
func udpEcho(t *testing.T) net.Addr {
	t.Helper()
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = c.WriteTo(b[:n], a)
		}
	}()
	return c.LocalAddr()
}
func metadata(t *testing.T, address string) *C.Metadata {
	t.Helper()
	m := &C.Metadata{}
	if e := m.SetRemoteAddress(address); e != nil {
		t.Fatal(e)
	}
	return m
}
func dial(t *testing.T, p C.Proxy, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, e := p.DialContext(ctx, metadata(t, address))
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func roundtrip(c net.Conn, payload []byte) error {
	if _, e := c.Write(payload); e != nil {
		return e
	}
	out := make([]byte, len(payload))
	if _, e := io.ReadFull(c, out); e != nil {
		return e
	}
	if !bytes.Equal(out, payload) {
		return fmt.Errorf("payload mismatch")
	}
	return nil
}
func await(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition timed out")
}

func TestForkServerRoundTripsAndRevocation(t *testing.T) {
	for _, protocol := range (&Core{}).Protocols() {
		t.Run(protocol, func(t *testing.T) {
			c, info, _ := fixture(t, protocol, []panel.UserInfo{subscriber})
			tag := t.Name()
			target := tcpEcho(t)
			p := client(t, info, subscriber)
			conn := dial(t, p, target)
			payload := bytes.Repeat([]byte("mihomo-wire-payload"), 13)
			if e := roundtrip(conn, payload); e != nil {
				t.Fatal(e)
			}
			await(t, func() bool {
				traffic, _ := c.GetUserTrafficSlice(tag, false)
				return len(traffic) == 1 && traffic[0].Upload == int64(len(payload)) && traffic[0].Download == int64(len(payload))
			})
			online, e := c.OnlineDevices(tag)
			if e != nil || len(online) != 1 || online[0].UID != subscriber.Id || online[0].IP != "127.0.0.1" {
				t.Fatalf("online=%v err=%v", online, e)
			}
			if protocol != "http" {
				dst := udpEcho(t)
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				m := metadata(t, dst.String())
				m.NetWork = C.UDP
				pc, e := p.ListenPacketContext(ctx, m)
				if e != nil {
					t.Fatal(e)
				}
				defer pc.Close()
				_ = pc.SetDeadline(time.Now().Add(4 * time.Second))
				if _, e = pc.WriteTo(payload, dst); e != nil {
					t.Fatal(e)
				}
				b := make([]byte, len(payload)+100)
				count, _, e := pc.ReadFrom(b)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(payload, b[:count]) {
					t.Fatal("UDP payload mismatch")
				}
				await(t, func() bool {
					v, _ := c.GetUserTrafficSlice(tag, false)
					return len(v) == 1 && v[0].Upload == 2*int64(len(payload)) && v[0].Download == 2*int64(len(payload))
				})
			}
			before, _ := c.GetUserTrafficSlice(tag, true)
			if len(before) != 1 {
				t.Fatal(before)
			}
			if e = c.DelUsers([]panel.UserInfo{subscriber}, tag, info); e != nil {
				t.Fatal(e)
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if e = roundtrip(conn, []byte("banned")); e == nil {
				t.Fatal("banned connection still forwards")
			}
			// A new handshake cannot regain access after removal (the empty listener
			// remains closed). Re-admission starts a fresh listener and authentication.
			bad := client(t, info, subscriber)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			unexpected, e := bad.DialContext(ctx, metadata(t, target))
			if e == nil {
				_ = unexpected.SetDeadline(time.Now().Add(time.Second))
				e = roundtrip(unexpected, []byte("blocked"))
				_ = unexpected.Close()
				if e == nil {
					t.Fatal("removed user reauthenticated")
				}
			}
			if _, e = c.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{subscriber}, NodeInfo: info}); e != nil {
				t.Fatal(e)
			}
			fresh := client(t, info, subscriber)
			active := dial(t, fresh, target)
			if e = roundtrip(active, []byte("unbanned")); e != nil {
				t.Fatal(e)
			}
			final, e := c.RetireNode(tag)
			if e != nil {
				t.Fatal(e)
			}
			var uploaded int64
			for _, v := range final {
				if v.UID != subscriber.Id {
					t.Fatal(v)
				}
				uploaded += v.Upload
			}
			if uploaded != 8 {
				t.Fatalf("final upload=%d", uploaded)
			}
		})
	}
}

func TestEmptyNodeCannotBecomeAnOpenProxy(t *testing.T) {
	for _, protocol := range []string{"http", "socks5", "mieru", "shadowquic"} {
		t.Run(protocol, func(t *testing.T) {
			_, info, _ := fixture(t, protocol, nil)
			c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Common.ServerPort)), 100*time.Millisecond)
			if e == nil {
				_ = c.Close()
				t.Fatal("empty node bound a port")
			}
		})
	}
}
func TestAdmissionAndIsolation(t *testing.T) {
	c, info, _ := fixture(t, "socks5", []panel.UserInfo{subscriber})
	tag := t.Name()
	n, _ := c.get(tag)
	n.mu.Lock()
	generation := n.generation
	n.mu.Unlock()
	m := &C.Metadata{InUser: subscriber.Uuid, NetWork: C.TCP, SrcIP: netip.MustParseAddr("198.51.100.1")}
	n.limiter.UpdateUserLimits(tag, []panel.UserInfo{{Id: subscriber.Id, Uuid: subscriber.Uuid, DeviceLimit: 1}})
	first, _, e := n.admit(m, generation, "198.51.100.1")
	if e != nil {
		t.Fatal(e)
	}
	if f, _, e := n.admit(m, generation, "198.51.100.2"); e == nil {
		n.finish(f)
		t.Fatal("second device accepted")
	}
	n.finish(first)
	if f, _, e := n.admit(m, generation-1, "198.51.100.1"); e == nil {
		n.finish(f)
		t.Fatal("stale listener generation accepted")
	}
	if _, e = c.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{{Id: 18, Uuid: subscriber.Uuid}}, NodeInfo: info}); e == nil {
		t.Fatal("shared identity accepted")
	}
}
