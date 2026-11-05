//go:build linux && acme_e2e

// Real ACME for the TrustTunnel core: V2bX's certificate manager (lego, HTTP-01
// on port 80) against local Pebble CAs, and the real endpoint binaries. This is
// what the other tests replace with fakes: issuance at AddNode, the renewal
// decision, delivery of a renewed pair to the live endpoint over TCP and QUIC,
// a web root when port 80 is taken, and a reload to a new hostname.
//
// Run it with scripts/e2e/trusttunnel-acme/run.sh, which starts the CAs and a
// mock DNS that resolves every name to 127.0.0.1. It needs root, for port 80.
package trusttunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/metacubex/quic-go"
	MTLS "github.com/metacubex/tls"
	log "github.com/sirupsen/logrus"
)

const acmeHost = "tt-acme.test"

// acmeCA is one Pebble CA: its ACME directory and the root it issues under.
type acmeCA struct {
	directory string
	roots     *x509.CertPool
}

// testCA reads the CA named by V2BX_TEST_ACME_<name> (its base URL) and
// V2BX_TEST_ACME_<name>_MGMT (its management URL), and points V2bX at it.
func testCA(t *testing.T, name string) acmeCA {
	t.Helper()
	base, mgmt := os.Getenv("V2BX_TEST_ACME_"+name), os.Getenv("V2BX_TEST_ACME_"+name+"_MGMT")
	if base == "" || mgmt == "" || os.Getenv("V2BX_TEST_TRUSTTUNNEL_BIN") == "" {
		t.Skip("run with scripts/e2e/trusttunnel-acme/run.sh")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // Pebble's management API on loopback.
	}}}
	resp, err := client.Get(mgmt + "/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	pemBytes, _ := io.ReadAll(resp.Body)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("no root from the CA")
	}
	t.Setenv("V2BX_TEST_ACME_DIRECTORY", base+"/dir")
	return acmeCA{directory: base + "/dir", roots: roots}
}

func acmeCore(t *testing.T) *TrustTunnel {
	t.Helper()
	core := &TrustTunnel{
		binDir: os.Getenv("V2BX_TEST_TRUSTTUNNEL_BIN"), workDir: t.TempDir(),
		nodes: make(map[string]*node), usersMap: make(map[string]map[string]int),
	}
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close() })
	return core
}

func acmeNode(port int, hostname string) *panel.NodeInfo {
	return &panel.NodeInfo{TrustTunnel: &panel.TrustTunnelNode{
		CommonNode: panel.CommonNode{ServerPort: port},
		Hostname:   hostname, CertType: "letsencrypt", AcmeEmail: "ops@example.com",
	}}
}

// servedTCP is the leaf the endpoint serves for hostname, its chain verified
// against roots as a subscriber's client would.
func servedTCP(ctx context.Context, addr, hostname string, roots *x509.CertPool) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	d := &tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: hostname, NextProtos: []string{"h2"}}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.(*tls.Conn).ConnectionState().PeerCertificates[0], nil
}

func servedQUIC(ctx context.Context, addr, hostname string, roots *x509.CertPool) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, addr, &MTLS.Config{RootCAs: roots, ServerName: hostname, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		return nil, err
	}
	defer c.CloseWithError(0, "")
	return c.ConnectionState().TLS.PeerCertificates[0], nil
}

func awaitServed(t *testing.T, ctx context.Context, addr, hostname string, roots *x509.CertPool) *x509.Certificate {
	t.Helper()
	for {
		c, err := servedTCP(ctx, addr, hostname, roots)
		if err == nil {
			return c
		}
		if ctx.Err() != nil {
			t.Fatalf("%s was never served with a verifiable chain: %v", hostname, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func awaitReady(n *node) {
	for !func() bool { n.mu.Lock(); defer n.mu.Unlock(); return n.ready }() {
		time.Sleep(50 * time.Millisecond)
	}
}

func describeLeaf(c *x509.Certificate) string {
	return fmt.Sprintf("serial %x from %q, valid %s", c.SerialNumber, c.Issuer.CommonName, c.NotAfter.Sub(c.NotBefore).Round(time.Hour))
}

// errorLog collects what V2bX logs at error level during a test.
type errorLog struct {
	mu      sync.Mutex
	entries []string
}

func (e *errorLog) Levels() []log.Level { return []log.Level{log.ErrorLevel} }
func (e *errorLog) Fire(entry *log.Entry) error {
	e.mu.Lock()
	e.entries = append(e.entries, entry.Message)
	e.mu.Unlock()
	return nil
}

func captureErrors(t *testing.T) *errorLog {
	e := &errorLog{}
	hooks := make(log.LevelHooks)
	for level, existing := range log.StandardLogger().Hooks {
		hooks[level] = append(hooks[level], existing...)
	}
	hooks.Add(e)
	previous := log.StandardLogger().ReplaceHooks(hooks)
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(previous) })
	return e
}

// A certificate with more than 30 days left is issued at AddNode, served over
// both transports, and left alone.
func TestACME_IssuesAtStartAndDoesNotRenewEarly(t *testing.T) {
	ca := testCA(t, "LONG")
	core := acmeCore(t)
	port, _ := freePort()
	start := time.Now()
	if err := core.AddNode("acme-issue", acmeNode(port, acmeHost), &conf.Options{ListenIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	t.Logf("AddNode, issuance included, took %s", time.Since(start).Round(time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	first := awaitServed(t, ctx, addr, acmeHost, ca.roots)
	t.Logf("TCP: %s", describeLeaf(first))
	q, err := servedQUIC(ctx, addr, acmeHost, ca.roots)
	if err != nil || q.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatalf("QUIC does not serve the issued certificate: %v", err)
	}
	time.Sleep(3*certificatePollInterval + time.Second)
	if got := awaitServed(t, ctx, addr, acmeHost, ca.roots); got.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatalf("a certificate with %s left was replaced", time.Until(first.NotAfter).Round(time.Hour))
	}
}

// 🔴 A certificate with 30 days or less is renewed at the first check, and the
// running endpoint serves the new one over TCP and QUIC without a restart. The
// renewal used to be judged by the clock read before it, and logged as a
// failure; nothing may be logged at error level.
func TestACME_RenewsWhenDueWithoutARestart(t *testing.T) {
	ca := testCA(t, "DUE")
	errs := captureErrors(t)
	core := acmeCore(t)
	port, _ := freePort()
	const tag = "acme-renew"
	if err := core.AddNode(tag, acmeNode(port, acmeHost), &conf.Options{ListenIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	n := core.nodes[tag]
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	first := awaitServed(t, ctx, addr, acmeHost, ca.roots)
	awaitReady(n)
	pid := nativeEndpointPID(n)
	for {
		got, err := servedTCP(ctx, addr, acmeHost, ca.roots)
		if err == nil && got.SerialNumber.Cmp(first.SerialNumber) != 0 {
			t.Logf("renewed: %s", describeLeaf(got))
			if nativeEndpointPID(n) != pid || syscall.Kill(pid, 0) != nil {
				t.Fatal("the renewal restarted the endpoint")
			}
			q, err := servedQUIC(ctx, addr, acmeHost, ca.roots)
			if err != nil || q.SerialNumber.Cmp(got.SerialNumber) != 0 {
				t.Fatalf("QUIC does not serve the renewed certificate: %v", err)
			}
			break
		}
		if ctx.Err() != nil {
			t.Fatal("a certificate with 29 days left was not renewed")
		}
		time.Sleep(200 * time.Millisecond)
	}
	errs.mu.Lock()
	defer errs.mu.Unlock()
	for _, e := range errs.entries {
		if strings.Contains(e, "certificate") {
			t.Fatalf("a successful renewal logged an error: %s", e)
		}
	}
}

// 🔴 Port 80 belongs to a web server: Let's Encrypt is answered through its web
// root, named in the node's own CertConfig. It used to be the built-in HTTP-01
// server or nothing.
func TestACME_WebRootWhilePort80IsTaken(t *testing.T) {
	ca := testCA(t, "LONG")
	webroot := t.TempDir()
	l, err := net.Listen("tcp", ":80")
	if err != nil {
		t.Fatal("port 80 must be free to start the stand-in web server:", err)
	}
	web := &http.Server{Handler: http.FileServer(http.Dir(webroot))}
	go func() { _ = web.Serve(l) }()
	defer web.Close()

	core := acmeCore(t)
	port, _ := freePort()
	opts := &conf.Options{ListenIP: "127.0.0.1", CertConfig: &conf.CertConfig{CertMode: "http", HTTPWebRoot: webroot}}
	if err := core.AddNode("acme-webroot", acmeNode(port, acmeHost), opts); err != nil {
		t.Fatal("issuance with port 80 held by a web server:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	t.Logf("issued through the web root: %s", describeLeaf(awaitServed(t, ctx, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), acmeHost, ca.roots)))
}

// 🔴 A reload to a new hostname, done as the controller does it: PrepareNode
// while the old endpoint serves, then retire it and AddNode. Issuance used to
// happen inside AddNode, after the old endpoint was gone.
func TestACME_NewHostnameIsIssuedWhileTheOldEndpointServes(t *testing.T) {
	for _, reachable := range []bool{true, false} {
		t.Run(map[bool]string{true: "authority answers", false: "authority unreachable"}[reachable], func(t *testing.T) {
			ca := testCA(t, "LONG")
			core := acmeCore(t)
			port, _ := freePort()
			const tag, newHost = "acme-reload", "tt-acme-renamed.test"
			opts := &conf.Options{ListenIP: "127.0.0.1"}
			if err := core.AddNode(tag, acmeNode(port, acmeHost), opts); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
			awaitServed(t, ctx, addr, acmeHost, ca.roots)
			if !reachable {
				t.Setenv("V2BX_TEST_ACME_DIRECTORY", "https://localhost:1/dir")
			}

			stop, probed := make(chan struct{}), make(chan [2]int)
			go func() {
				served, failed := 0, 0
				for {
					if _, err := servedTCP(ctx, addr, acmeHost, ca.roots); err == nil {
						served++
					} else {
						failed++
					}
					select {
					case <-stop:
						probed <- [2]int{served, failed}
						return
					case <-time.After(100 * time.Millisecond):
					}
				}
			}()
			start := time.Now()
			err := core.PrepareNode(tag, acmeNode(port, newHost), opts)
			took := time.Since(start)
			close(stop)
			counts := <-probed
			t.Logf("PrepareNode took %s; the old endpoint answered %d of %d probes meanwhile", took.Round(time.Millisecond), counts[0], counts[0]+counts[1])
			if counts[1] != 0 {
				t.Fatalf("the old endpoint stopped serving during preparation")
			}
			if !reachable {
				if err == nil {
					t.Fatal("preparation succeeded against an unreachable authority")
				}
				if _, err := servedTCP(ctx, addr, acmeHost, ca.roots); err != nil {
					t.Fatal("the old endpoint is gone after a failed preparation:", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			retired := time.Now()
			if err := core.DelNode(tag); err != nil {
				t.Fatal(err)
			}
			if err := core.AddNode(tag, acmeNode(port, newHost), opts); err != nil {
				t.Fatal(err)
			}
			got := awaitServed(t, ctx, addr, newHost, ca.roots)
			t.Logf("the new hostname was served %s after the old endpoint was retired: %s", time.Since(retired).Round(time.Millisecond), describeLeaf(got))
		})
	}
}
