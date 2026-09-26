//go:build soak

package sing

// Soak harness: a real anytls inbound (as on the nodes) behind V2bX's hook and
// limiter, driven by a real sing-box anytls client, measuring what is left
// behind after each traffic pattern. Run with:
//
//	go test -tags "soak <release tags>" -run TestSoak -v ./core/sing/

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

func writeSelfSigned(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "node.test"},
		DNSNames:     []string{"node.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	cert := filepath.Join(dir, "c.pem")
	kf := filepath.Join(dir, "k.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cert, kf
}

type soakRig struct {
	server     *Sing
	tag        string
	socksPort  int
	serverPort int
}

func startSoakRig(t *testing.T) *soakRig {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile := writeSelfSigned(t, dir)

	origin := filepath.Join(dir, "origin.json")
	os.WriteFile(origin, []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`), 0o644)
	sc := conf.NewSingConfig()
	sc.OriginalPath = origin
	sc.LogConfig.Disabled = true
	sc.AllowPrivateDestinations = true // targets live on loopback here
	core, err := New(&conf.CoreConfig{Type: "sing", SingConfig: sc})
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	s := core.(*Sing)

	port := freeTCPPort(t)
	tag := "soak-anytls"
	users := []panel.UserInfo{{Id: 1, Uuid: "0e6d2c64-0000-4000-8000-000000000001"}}
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, nil)
	common := panel.CommonNode{ServerPort: port, ServerName: "node.test"}
	info := &panel.NodeInfo{
		Id: 1, Type: "anytls", Security: panel.Tls,
		AnyTls: &panel.AnyTlsNode{CommonNode: common},
		Common: &common,
	}
	opts := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}
	opts.CertConfig = &conf.CertConfig{CertMode: "file", CertFile: certFile, KeyFile: keyFile}
	decoyOff := false
	opts.SingOptions.DecoySite = &decoyOff
	if err := s.AddNode(tag, info, opts); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if _, err := s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatalf("AddUsers: %v", err)
	}

	socks := freeTCPPort(t)
	clientCfg := fmt.Sprintf(`{
	  "log":{"disabled":true},
	  "inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],
	  "outbounds":[{"type":"anytls","tag":"proxy","server":"127.0.0.1","server_port":%d,
	    "password":%q,"tls":{"enabled":true,"server_name":"node.test","insecure":true}}],
	  "route":{"final":"proxy"}
	}`, socks, port, users[0].Uuid)
	ctx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(),
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
	copts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(clientCfg))
	if err != nil {
		t.Fatal(err)
	}
	client, err := box.New(box.Options{Context: ctx, Options: copts})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return &soakRig{server: s, tag: tag, socksPort: socks, serverPort: port}
}

// socksConnect opens a CONNECT through the client's SOCKS inbound.
func socksConnect(port int, target string) (net.Conn, error) {
	host, ps, _ := net.SplitHostPort(target)
	var p int
	fmt.Sscanf(ps, "%d", &p)
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil {
		c.Close()
		return nil, err
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(p))
	c.Write(req)
	head := make([]byte, 10)
	if _, err := io.ReadFull(c, head); err != nil || head[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("connect refused")
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// trackedOpen is how many user connections the hook still holds open.
func (r *soakRig) trackedOpen() int {
	n := 0
	r.server.hookServer.conns.Range(func(_, v any) bool {
		uc := v.(*userConns)
		uc.mu.Lock()
		n += len(uc.m)
		uc.mu.Unlock()
		return true
	})
	return n
}

func settle(t *testing.T, r *soakRig, label string, base int) (int, int) {
	t.Helper()
	var tracked, gor int
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		runtime.GC()
		tracked, gor = r.trackedOpen(), runtime.NumGoroutine()
		if tracked == 0 && gor <= base+5 {
			break
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("%-38s tracked-open=%5d goroutines=%5d (base %d) heap=%6.1f MB",
		label, tracked, gor, base, float64(ms.HeapInuse)/1e6)
	return tracked, gor
}

func listen(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return ln.Addr().String()
}

func TestSoak(t *testing.T) {
	r := startSoakRig(t)
	echo := listen(t, func(c net.Conn) { defer c.Close(); io.Copy(c, c) })
	// A server that accepts and then says nothing and never closes - like a
	// long-poll or push endpoint whose client has gone away.
	var silentMu sync.Mutex
	var silent []net.Conn
	quiet := listen(t, func(c net.Conn) { silentMu.Lock(); silent = append(silent, c); silentMu.Unlock() })

	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	base := runtime.NumGoroutine()
	t.Logf("baseline goroutines=%d", base)

	const n = 300
	run := func(label string, fn func() error) (int, int) {
		var wg sync.WaitGroup
		errs := 0
		var mu sync.Mutex
		sem := make(chan struct{}, 50)
		for i := 0; i < n; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if err := fn(); err != nil {
					mu.Lock()
					errs++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if errs > 0 {
			t.Logf("%s: %d/%d failed", label, errs, n)
		}
		return settle(t, r, label, base)
	}

	// 1. Plain request/response, closed normally.
	run("1 echo, closed normally", func() error {
		c, err := socksConnect(r.socksPort, echo)
		if err != nil {
			return err
		}
		defer c.Close()
		c.Write(make([]byte, 1024))
		_, err = io.ReadFull(c, make([]byte, 1024))
		return err
	})
	// 2. The user closes; the remote stays open and silent.
	run("2 user closes, remote silent", func() error {
		c, err := socksConnect(r.socksPort, quiet)
		if err != nil {
			return err
		}
		c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		time.Sleep(20 * time.Millisecond)
		return c.Close()
	})
	// 3. The user half-closes (FIN) and then goes away; remote silent.
	run("3 user half-closes, remote silent", func() error {
		c, err := socksConnect(r.socksPort, quiet)
		if err != nil {
			return err
		}
		c.(*net.TCPConn).CloseWrite()
		time.Sleep(20 * time.Millisecond)
		return c.Close()
	})
	// 4. The remote closes first.
	silentMu.Lock()
	for _, c := range silent {
		c.Close()
	}
	silent = nil
	silentMu.Unlock()
	settle(t, r, "4 after the silent remotes close", base)

	// Idle anytls sessions are pooled by the client and expire after its
	// idle_session_timeout (30 s default). Wait past that.
	time.Sleep(45 * time.Second)
	settle(t, r, "5 after 45 s idle", base)
	dumpGoroutines(t)
}

// dumpGoroutines prints where the leftover goroutines are parked, grouped.
func dumpGoroutines(t *testing.T) {
	buf := make([]byte, 8<<20)
	n := runtime.Stack(buf, true)
	counts := map[string]int{}
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		lines := strings.Split(g, "\n")
		key := ""
		for i := 1; i+1 < len(lines) && len(key) < 400; i += 2 {
			fn := strings.TrimSpace(lines[i])
			if strings.HasPrefix(fn, "runtime.") || strings.HasPrefix(fn, "internal/poll") || strings.HasPrefix(fn, "sync.") {
				continue
			}
			key += fn + " <- "
			if strings.Count(key, "<-") >= 3 {
				break
			}
		}
		counts[key]++
	}
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range counts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	for i, e := range list {
		if i >= 12 {
			break
		}
		t.Logf("%4d  %s", e.v, e.k)
	}
}

// anytlsSessionsHeld counts the entries in the anytls inbound's userconns map
// (unexported, so read through reflect+unsafe).
func anytlsSessionsHeld(t *testing.T, r *soakRig) int {
	t.Helper()
	in, ok := r.server.box.Inbound().Get(r.tag)
	if !ok {
		t.Fatal("inbound not found")
	}
	f := reflect.ValueOf(in).Elem().FieldByName("userconns")
	m := (*sync.Map)(unsafe.Pointer(f.UnsafeAddr()))
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// A session that authenticates and ends without opening a stream - a phone
// dropping right after the handshake, or a client's pre-opened idle session -
// must not stay in userconns.
func TestSoakAnytlsEmptySessions(t *testing.T) {
	r := startSoakRig(t)
	sum := sha256.Sum256([]byte("0e6d2c64-0000-4000-8000-000000000001"))
	const n = 3000
	before := anytlsSessionsHeld(t, r)
	runtime.GC()
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	for i := 0; i < n; i++ {
		c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", r.serverPort), &tls.Config{InsecureSkipVerify: true, ServerName: "node.test"})
		if err != nil {
			t.Fatal(err)
		}
		c.Write(append(sum[:], 0, 0)) // password hash, zero padding: authenticated
		time.Sleep(time.Millisecond)
		c.Close()
	}
	time.Sleep(time.Second)
	runtime.GC()
	after := anytlsSessionsHeld(t, r)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("userconns: before=%d after %d empty sessions=%d, heap %.1f -> %.1f MB (%.1f KB per session)", before, n, after,
		float64(ms0.HeapInuse)/1e6, float64(ms.HeapInuse)/1e6, float64(int64(ms.HeapInuse)-int64(ms0.HeapInuse))/1024/float64(n))
	if after-before > 5 {
		t.Fatalf("%d of %d closed sessions are still held", after-before, n)
	}
}
