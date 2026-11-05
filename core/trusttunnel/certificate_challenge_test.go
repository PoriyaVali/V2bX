package trusttunnel

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

// 🔴 A renewal was judged by the clock read before it began. A certificate
// starts when it is issued - Pebble does not backdate - so every such renewal
// was logged as "certificate maintenance failed ... outside its validity
// period" and its pair waited a poll to reach the endpoint. Seen against a real
// Pebble CA with the real endpoint.
func TestRenewedCertificateIsJudgedByTheClockAfterTheRenewal(t *testing.T) {
	p := validConfigParams()
	p.CertType, p.AcmeEmail = "letsencrypt", "admin@example.test"
	core := &TrustTunnel{certificateOps: testCertificateOperations{
		ensure: isolatedCertificateOperations(t).Ensure,
		renew: func(config *conf.CertConfig) error {
			issued := time.Now()
			cert, key := endpointCertificatePEM(t, config.CertDomain, issued, issued.Add(90*24*time.Hour))
			return writeEndpointSource(config, cert, key)
		},
	}}
	c, err := core.newCertificateLifecycle(t.TempDir(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.prepare()
	if err != nil {
		t.Fatal(err)
	}
	writeEndpointHosts(t, c.dir, p.Hostname, initial)
	publishes := 0
	// The refresh began two seconds before the authority issued: an ACME order
	// takes that long. X.509 times are whole seconds, so less would not show.
	started := time.Now().Add(-2 * time.Second)
	if err := c.refresh(started, func(commit func() error) error { publishes++; return commit() }); err != nil || publishes != 1 {
		t.Fatalf("a successful renewal was not published in the same refresh: %v, publishes=%d", err, publishes)
	}
	if !c.nextRenew.Equal(started.Add(certificateRenewInterval)) {
		t.Fatal("the next renewal check moved with the clock used to judge the pair")
	}
}

// 🔴 Let's Encrypt was answered only by a built-in HTTP-01 server on port 80.
// With a web server or another node there, issuance and renewal always failed,
// and the error advised CertMode dns or HTTPWebRoot - both ignored by this
// core. The node's CertConfig now chooses the challenge, and only that.
func TestLetsEncryptTakesOnlyTheChallengeFromTheNodeConfig(t *testing.T) {
	core := &TrustTunnel{}
	dir := t.TempDir()
	le := &panel.TrustTunnelNode{Hostname: "le.example.test", CertType: "letsencrypt", AcmeEmail: "ops@example.test"}
	base, err := core.newCertificateLifecycle(dir, le, nil)
	if err != nil {
		t.Fatal(err)
	}
	if base.config.CertMode != "http" || base.config.HTTPWebRoot != "" || base.config.Provider != "" {
		t.Fatalf("default challenge changed: %+v", base.config)
	}
	samePlace := func(t *testing.T, got *conf.CertConfig) {
		t.Helper()
		if got.CertDomain != le.Hostname || got.Email != le.AcmeEmail {
			t.Fatalf("the node config chose the certificate's name or account: %+v", got)
		}
		// The same files: switching the challenge must not re-issue.
		if got.CertFile != base.config.CertFile || got.KeyFile != base.config.KeyFile || got.AccountDir != base.config.AccountDir {
			t.Fatalf("the challenge moved the certificate: %+v", got)
		}
	}
	// What else the node config says about certificates is not this core's.
	local := func(c conf.CertConfig) *conf.Options {
		c.CertDomain, c.Email = "other.example.test", "other@example.test"
		c.CertFile, c.KeyFile, c.AccountDir = "/elsewhere/cert.pem", "/elsewhere/key.pem", "/elsewhere/accounts"
		return &conf.Options{CertConfig: &c}
	}

	t.Run("dns", func(t *testing.T) {
		env := map[string]string{"CF_DNS_API_TOKEN": "token"}
		c, err := core.newCertificateLifecycle(dir, le, local(conf.CertConfig{CertMode: "dns", Provider: "cloudflare", DNSEnv: env}))
		if err != nil {
			t.Fatal(err)
		}
		if c.config.CertMode != "dns" || c.config.Provider != "cloudflare" || !reflect.DeepEqual(c.config.DNSEnv, env) {
			t.Fatalf("DNS-01 was not taken from the node config: %+v", c.config)
		}
		env["CF_DNS_API_TOKEN"] = "changed later"
		if c.config.DNSEnv["CF_DNS_API_TOKEN"] != "token" {
			t.Fatal("the lifecycle shares the node config's DNS environment map")
		}
		samePlace(t, c.config)
	})
	t.Run("webroot", func(t *testing.T) {
		c, err := core.newCertificateLifecycle(dir, le, local(conf.CertConfig{CertMode: "http", HTTPWebRoot: "/var/www/html"}))
		if err != nil {
			t.Fatal(err)
		}
		if c.config.CertMode != "http" || c.config.HTTPWebRoot != "/var/www/html" {
			t.Fatalf("the web root was not taken from the node config: %+v", c.config)
		}
		samePlace(t, c.config)
	})
	t.Run("nothing to say", func(t *testing.T) {
		c, err := core.newCertificateLifecycle(dir, le, &conf.Options{CertConfig: conf.NewCertConfig()})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(c.config, base.config) {
			t.Fatalf("a default node config changed Let's Encrypt: %+v", c.config)
		}
	})
	t.Run("not letsencrypt", func(t *testing.T) {
		self := &panel.TrustTunnelNode{Hostname: le.Hostname, CertType: "self-signed"}
		c, err := core.newCertificateLifecycle(dir, self, local(conf.CertConfig{CertMode: "dns", Provider: "cloudflare", HTTPWebRoot: "/var/www/html"}))
		if err != nil {
			t.Fatal(err)
		}
		if c.config.CertMode != "self" || c.config.Provider != "" || c.config.HTTPWebRoot != "" {
			t.Fatalf("a challenge setting reached a certificate that has no challenge: %+v", c.config)
		}
	})
}

// 🔴 The other half of a reload's certificate fix: PrepareNode must issue what
// AddNode will use, before the old endpoint is retired, and leave everything
// that endpoint reads alone.
func TestPrepareNodeIssuesAheadWithoutTouchingTheRunningEndpoint(t *testing.T) {
	work := t.TempDir()
	isolated := isolatedCertificateOperations(t)
	var ensured []string
	core := &TrustTunnel{workDir: work, certificateOps: testCertificateOperations{ensure: func(c *conf.CertConfig) error {
		ensured = append(ensured, c.CertDomain)
		return isolated.Ensure(c)
	}}}
	const tag = "prepare-node"
	dir := filepath.Join(work, sanitizeTag(tag))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	running := []byte("# what the running endpoint was started with\n")
	for _, name := range []string{"hosts.toml", "vpn.toml", "credentials.toml"} {
		if err := os.WriteFile(filepath.Join(dir, name), running, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := validConfigParams()
	p.Hostname, p.CertType, p.AcmeEmail = "new-name.example.test", "letsencrypt", "ops@example.test"
	if err := core.PrepareNode(tag, &panel.NodeInfo{TrustTunnel: p}, &conf.Options{}); err != nil {
		t.Fatal(err)
	}
	if len(ensured) != 1 || ensured[0] != p.Hostname {
		t.Fatalf("the new name's certificate was not prepared: %v", ensured)
	}
	for _, name := range []string{"hosts.toml", "vpn.toml", "credentials.toml"} {
		if got, _ := os.ReadFile(filepath.Join(dir, name)); !bytes.Equal(got, running) {
			t.Fatalf("preparing rewrote %s under the running endpoint", name)
		}
	}
	// AddNode's preparation now finds it in place.
	next, err := core.newCertificateLifecycle(dir, p, &conf.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.snapshot(time.Now()); err != nil {
		t.Fatalf("AddNode would not find the prepared certificate: %v", err)
	}
}

func TestPrepareNodeRejectsWhatAddNodeWouldWithoutIssuing(t *testing.T) {
	issued := 0
	core := &TrustTunnel{workDir: t.TempDir(), certificateOps: testCertificateOperations{ensure: func(*conf.CertConfig) error {
		issued++
		return nil
	}}}
	for name, edit := range map[string]func(*panel.TrustTunnelNode){
		"letsencrypt without an email": func(p *panel.TrustTunnelNode) { p.CertType, p.AcmeEmail = "letsencrypt", "" },
		"hostname with a port":         func(p *panel.TrustTunnelNode) { p.Hostname = "example.test:443" },
		"no server port":               func(p *panel.TrustTunnelNode) { p.ServerPort = 0 },
		"unknown certificate type":     func(p *panel.TrustTunnelNode) { p.CertType = "acme" },
	} {
		p := validConfigParams()
		edit(p)
		if err := core.PrepareNode("rejected", &panel.NodeInfo{TrustTunnel: p}, &conf.Options{}); err == nil {
			t.Errorf("%s: prepared a node AddNode rejects", name)
		}
	}
	if issued != 0 {
		t.Fatalf("certificates were issued for %d rejected nodes", issued)
	}
	if err := core.PrepareNode("not-trusttunnel", &panel.NodeInfo{}, &conf.Options{}); err != nil {
		t.Fatal("a node without TrustTunnel parameters is AddNode's to report:", err)
	}
	failing := &TrustTunnel{workDir: t.TempDir(), certificateOps: testCertificateOperations{ensure: func(*conf.CertConfig) error {
		return errors.New("authority unreachable")
	}}}
	p := validConfigParams()
	p.CertType, p.AcmeEmail = "letsencrypt", "ops@example.test"
	if err := failing.PrepareNode("unreachable", &panel.NodeInfo{TrustTunnel: p}, &conf.Options{}); err == nil || !strings.Contains(err.Error(), "authority unreachable") {
		t.Fatalf("a failed issuance was not reported: %v", err)
	}
}

// 🔴 Readiness was given up for good after readyTimeout. An endpoint that
// answered later was never signalled, so every user change after it - removing
// a user included - waited for the endpoint's next restart.
func TestReadinessIsPolledPastTheFastWindow(t *testing.T) {
	oldTimeout, oldPoll, oldSlow := readyTimeout, readyPollInterval, slowReadyPollInterval
	readyTimeout, readyPollInterval, slowReadyPollInterval = 100*time.Millisecond, 10*time.Millisecond, 30*time.Millisecond
	t.Cleanup(func() { readyTimeout, readyPollInterval, slowReadyPollInterval = oldTimeout, oldPoll, oldSlow })

	mark := filepath.Join(t.TempDir(), "reloaded")
	// Stands in for the endpoint: it records the reload it is sent.
	cmd := exec.Command("sh", "-c", `trap 'touch "$0"' HUP; while :; do sleep 0.02; done`, mark)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	n := &node{tag: "late", metricsPort: port, cmd: cmd, pendingReload: true, stop: make(chan struct{})}
	done := make(chan struct{})
	go func() { n.waitReady(cmd); close(done) }()

	time.Sleep(3 * readyTimeout)
	n.mu.Lock()
	early := n.ready
	n.mu.Unlock()
	if early {
		t.Fatal("ready before the metrics port answered")
	}
	server := lateMetricsServer(t, port)
	defer server.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readiness was given up: a late endpoint is never signalled")
	}
	n.mu.Lock()
	ready, pending := n.ready, n.pendingReload
	n.mu.Unlock()
	if !ready || pending {
		t.Fatalf("late readiness did not deliver the pending reload: ready=%v pending=%v", ready, pending)
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(mark); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the late endpoint never received its reload")
		}
	}
}

// lateMetricsServer answers the endpoint's drain on port, as a live endpoint
// does once it is up.
func lateMetricsServer(t *testing.T, port int) *http.Server {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	})}
	go func() { _ = server.Serve(l) }()
	return server
}
