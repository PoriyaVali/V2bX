//go:build linux

package trusttunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"golang.org/x/net/http2"
)

// Opt in with V2BX_TEST_TRUSTTUNNEL_BIN pointing to a directory containing the
// real trusttunnel_endpoint and setup_wizard. All listeners and destinations
// are loopback; generated certificates and credentials live in t.TempDir().
func TestNativeEndpoint_StartupSyncAndReload(t *testing.T) {
	binDir := strings.TrimSpace(os.Getenv("V2BX_TEST_TRUSTTUNNEL_BIN"))
	if binDir == "" {
		t.Skip("set V2BX_TEST_TRUSTTUNNEL_BIN to run the real Linux endpoint integration test")
	}
	var err error
	binDir, err = filepath.Abs(binDir)
	if err != nil {
		t.Fatal(err)
	}
	core := &TrustTunnel{
		binDir: binDir, workDir: t.TempDir(),
		nodes: make(map[string]*node), usersMap: make(map[string]map[string]int),
	}
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	metricsPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	for metricsPort == port {
		metricsPort, err = freePort()
		if err != nil {
			t.Fatal(err)
		}
	}
	const tag = "native-startup-reload"
	dir := filepath.Join(core.workDir, tag)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	params := &panel.TrustTunnelNode{
		CommonNode: panel.CommonNode{ServerPort: port},
		Hostname:   "native.test", CertType: "self-signed",
	}
	if err := core.generateConfig(dir, params, metricsPort, &conf.Options{ListenIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	// The destination is an isolated local echo server, never a public service.
	if err := setTopLevel(filepath.Join(dir, "vpn.toml"), "allow_private_network_connections", "true"); err != nil {
		t.Fatal(err)
	}
	gate := &nativeReadinessGate{
		transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext},
		observed:  make(chan struct{}), released: make(chan struct{}),
	}
	n := &node{
		tag: tag, dir: dir, metricsPort: metricsPort, users: make(map[string]string),
		done: make(chan struct{}), stop: make(chan struct{}),
	}
	n.metricsOnce.Do(func() {
		n.metricsClient = &http.Client{Timeout: 30 * time.Second, Transport: gate}
	})
	if err := n.start(core.binPath(endpointBin)); err != nil {
		gate.CloseIdleConnections()
		t.Fatal(err)
	}
	go n.supervise(core.binPath(endpointBin))
	core.nodes[tag] = n
	t.Cleanup(func() {
		gate.open()
		if err := core.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-n.done:
		case <-time.After(3 * time.Second):
			t.Error("native endpoint supervision did not terminate")
		}
	})
	pid := nativeEndpointPID(n)
	if pid == 0 {
		t.Fatal("endpoint was not started")
	}
	assertPID := func() error {
		if got := nativeEndpointPID(n); got != pid {
			return fmt.Errorf("endpoint restarted: PID changed from %d to %d", pid, got)
		}
		return syscall.Kill(pid, 0)
	}
	credentialsPath := filepath.Join(dir, "credentials.toml")
	initial, err := os.ReadFile(credentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial) == 0 || bytes.Contains(initial, []byte("placeholder")) {
		t.Fatal("endpoint startup credentials are empty or contain the fixed placeholder")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	select {
	case <-gate.observed:
	case <-ctx.Done():
		t.Fatal("native endpoint never served metrics before startup user sync:", ctx.Err())
	}
	n.mu.Lock()
	ready := n.ready
	n.mu.Unlock()
	if ready {
		t.Fatal("readiness gate did not hold the startup user sync window")
	}
	userA := panel.UserInfo{Id: 1, Uuid: "00000000-0000-4000-8000-000000000001"}
	userB := panel.UserInfo{Id: 2, Uuid: "00000000-0000-4000-8000-000000000002"}
	if added, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{userA}}); err != nil || added != 1 {
		t.Fatalf("startup AddUsers = %d, %v", added, err)
	}
	// Metrics prove the endpoint has already parsed its original credentials.
	// Releasing readiness must replay the update made after that parse.
	gate.open()
	target := nativeEchoTarget(t)
	endpoint := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	probe := func(user string, want int) error {
		if err := assertPID(); err != nil {
			return err
		}
		status, err := nativeConnect(ctx, endpoint, target, user)
		if err != nil {
			return err
		}
		if status != want {
			return fmt.Errorf("CONNECT returned %d, want %d", status, want)
		}
		return nil
	}
	nativeAwait(t, ctx, "initial user sync reaches real authentication", func() error { return probe(userA.Uuid, http.StatusOK) })
	if err := probe(userB.Uuid, http.StatusProxyAuthRequired); err != nil {
		t.Fatal("unknown user:", err)
	}
	if err := probe("placeholder", http.StatusProxyAuthRequired); err != nil {
		t.Fatal("fixed bootstrap credential:", err)
	}
	if err := core.DelUsers([]panel.UserInfo{userA}, tag, nil); err != nil {
		t.Fatal(err)
	}
	empty, err := os.ReadFile(credentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) == 0 || bytes.Contains(empty, []byte(userA.Uuid)) || bytes.Contains(empty, []byte("placeholder")) {
		t.Fatal("deleting the last user did not leave a nonempty random sentinel")
	}
	nativeAwait(t, ctx, "removing last user revokes native authentication", func() error { return probe(userA.Uuid, http.StatusProxyAuthRequired) })
	if added, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{userB}}); err != nil || added != 1 {
		t.Fatalf("re-add users = %d, %v", added, err)
	}
	nativeAwait(t, ctx, "re-added user authenticates without restarting", func() error { return probe(userB.Uuid, http.StatusOK) })
	if err := probe(userA.Uuid, http.StatusProxyAuthRequired); err != nil {
		t.Fatal("removed user became valid again:", err)
	}
	if err := assertPID(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeEndpoint_ProvidedCertificateRotation(t *testing.T) {
	binDir := strings.TrimSpace(os.Getenv("V2BX_TEST_TRUSTTUNNEL_BIN"))
	if binDir == "" {
		t.Skip("set V2BX_TEST_TRUSTTUNNEL_BIN to run real Linux certificate reload testing")
	}
	binDir, err := filepath.Abs(binDir)
	if err != nil {
		t.Fatal(err)
	}
	core := &TrustTunnel{
		binDir: binDir, workDir: t.TempDir(),
		nodes: make(map[string]*node), usersMap: make(map[string]map[string]int),
	}
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	p := &panel.TrustTunnelNode{
		CommonNode: panel.CommonNode{ServerPort: port},
		Hostname:   "native.test", CertType: "provided",
	}
	p.CertChainPath, p.CertKeyPath = providedCertificateFixture(t, p.Hostname, "other-cn.test")
	initialPair, err := tls.LoadX509KeyPair(p.CertChainPath, p.CertKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	const tag = "native-certificate-rotation"
	if err := core.AddNode(tag, &panel.NodeInfo{TrustTunnel: p}, &conf.Options{ListenIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	n := core.nodes[tag]
	t.Cleanup(func() {
		if err := core.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-n.done:
		case <-time.After(3 * time.Second):
			t.Error("certificate test endpoint was not reaped")
		}
	})
	pid := nativeEndpointPID(n)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	endpoint := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	probe := func(want []byte) error {
		if nativeEndpointPID(n) != pid || syscall.Kill(pid, 0) != nil {
			return fmt.Errorf("native certificate reload restarted or lost its process")
		}
		got, err := nativePeerCertificate(ctx, endpoint)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("native TLS served a different certificate")
		}
		return nil
	}
	nativeAwait(t, ctx, "provided SAN with different CN serves the panel hostname", func() error { return probe(initialPair.Certificate[0]) })
	nativeAwait(t, ctx, "provided endpoint becomes reloadable", func() error {
		n.mu.Lock()
		defer n.mu.Unlock()
		if !n.ready {
			return fmt.Errorf("waiting for metrics readiness")
		}
		return nil
	})
	certPEM, keyPEM := endpointCertificatePEM(t, p.Hostname, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	nextPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.CertChainPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Exercise an unrelated SIGHUP while the external pair is mismatched. The
	// endpoint must still load its immutable previous snapshot successfully.
	if _, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{{Id: 1, Uuid: "certificate-rotation-user"}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-time.After(certificatePollInterval + 250*time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := probe(initialPair.Certificate[0]); err != nil {
		t.Fatal("partial external certificate update damaged live TLS:", err)
	}
	if err := os.WriteFile(p.CertKeyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	nativeAwait(t, ctx, "complete external pair reaches live native TLS without restart", func() error { return probe(nextPair.Certificate[0]) })
}

func nativePeerCertificate(parent context.Context, endpoint string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{
		ServerName: "native.test", NextProtos: []string{"h2"},
		InsecureSkipVerify: true, // Generated self-signed loopback fixture only.
	}}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("native TLS returned no certificate")
	}
	return append([]byte(nil), state.PeerCertificates[0].Raw...), nil
}

type nativeReadinessGate struct {
	transport *http.Transport
	observed  chan struct{}
	released  chan struct{}
	seenOnce  sync.Once
	openOnce  sync.Once
}

func (g *nativeReadinessGate) open() { g.openOnce.Do(func() { close(g.released) }) }

func (g *nativeReadinessGate) CloseIdleConnections() { g.transport.CloseIdleConnections() }

func (g *nativeReadinessGate) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := g.transport.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	g.seenOnce.Do(func() { close(g.observed) })
	select {
	case <-g.released:
		return resp, nil
	case <-req.Context().Done():
		resp.Body.Close()
		return nil, req.Context().Err()
	}
}

func nativeEndpointPID(n *node) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cmd == nil || n.cmd.Process == nil {
		return 0
	}
	return n.cmd.Process.Pid
}

func nativeAwait(t *testing.T, ctx context.Context, description string, probe func() error) {
	t.Helper()
	var last error
	for {
		if last = probe(); last == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v (last result: %v)", description, ctx.Err(), last)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func nativeEchoTarget(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var handlers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-done
		handlers.Wait()
	})
	return l.Addr().String()
}

func nativeConnect(parent context.Context, endpoint, target, user string) (int, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{
		ServerName: "native.test", NextProtos: []string{"h2"},
		InsecureSkipVerify: true, // Only the generated self-signed loopback fixture.
	}}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if state := conn.(*tls.Conn).ConnectionState(); state.NegotiatedProtocol != "h2" {
		return 0, fmt.Errorf("endpoint negotiated ALPN %q, want h2", state.NegotiatedProtocol)
	}
	h2, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		return 0, err
	}
	defer h2.Close()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+target, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+user)))
	resp, err := h2.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	payload := []byte("native TrustTunnel authenticated echo\n")
	if _, err := writer.Write(payload); err != nil {
		return resp.StatusCode, err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		return resp.StatusCode, err
	}
	if !bytes.Equal(got, payload) {
		return resp.StatusCode, fmt.Errorf("authenticated tunnel did not echo its payload")
	}
	return resp.StatusCode, nil
}
