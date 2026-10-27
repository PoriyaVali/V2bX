package node

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/common/task"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/internal/certtest"
	"github.com/PoriyaVali/V2bX/limiter"
)

func taskCertificate(t *testing.T, mode string) *conf.CertConfig {
	t.Helper()
	dir := t.TempDir()
	c := &conf.CertConfig{CertMode: mode, CertDomain: "node.example.test", CertFile: filepath.Join(dir, "certificate.pem"), KeyFile: filepath.Join(dir, "private.key"), Provider: "test-provider"}
	ca := certtest.NewAuthority(t)
	certtest.Write(t, c.CertFile, c.KeyFile, ca.Issue(t, c.CertDomain, 1, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	return c
}

func TestCertificateRenewalScheduleFollowsModeAndPanelSecurity(t *testing.T) {
	for _, mode := range []string{"", "none", "file", "self", "http", "dns"} {
		t.Run(mode, func(t *testing.T) {
			c := &Controller{Options: &conf.Options{CertConfig: taskCertificate(t, mode)}}
			t.Cleanup(func() {
				if c.renewCertPeriodic != nil {
					c.renewCertPeriodic.Close()
					c.renewCertPeriodic.Wait()
				}
			})
			info := &panel.NodeInfo{Type: "anytls", Security: panel.Reality}
			c.configureCertificateRenewal(info)
			if c.renewCertPeriodic != nil {
				t.Fatal("REALITY started certificate renewal")
			}
			info.Security = panel.Tls
			c.configureCertificateRenewal(info)
			want := mode == "self" || mode == "http" || mode == "dns"
			if (c.renewCertPeriodic != nil) != want {
				t.Fatalf("mode %q: renewal required=%v", mode, want)
			}
			if want && (c.renewCertPeriodic.Interval != 6*time.Hour || !c.renewCertPeriodic.Running()) {
				t.Fatal("managed/self renewal is not scheduled every six hours")
			}
			info.Security = panel.Reality
			c.configureCertificateRenewal(info)
			if c.renewCertPeriodic != nil {
				t.Fatal("switching away from TLS retained a renewal loop")
			}
			info.Security, info.Type = panel.Tls, "trusttunnel"
			c.configureCertificateRenewal(info)
			if c.renewCertPeriodic != nil {
				t.Fatal("TrustTunnel started a second generic certificate manager")
			}
			c.Options.Core = "mihomo"
			c.configureCertificateRenewal(info)
			if (c.renewCertPeriodic != nil) != want {
				t.Fatalf("embedded Mihomo TrustTunnel renewal required=%v, want %v", c.renewCertPeriodic != nil, want)
			}
		})
	}
	(&Controller{Options: &conf.Options{}}).configureCertificateRenewal(&panel.NodeInfo{Security: panel.Tls})
}

func TestCertificateTaskRetriesAfterProviderConfigurationFailure(t *testing.T) {
	c := &Controller{Options: &conf.Options{CertConfig: &conf.CertConfig{CertMode: "dns", CertDomain: "node.example.test", CertFile: "unused.pem", KeyFile: "unused.key"}}}
	var attempts atomic.Int32
	task := &task.Task{Interval: 5 * time.Millisecond, Execute: func() error {
		attempts.Add(1)
		return c.renewCertTask() // Missing provider fails before any network request.
	}}
	if err := task.Start(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { task.Close(); task.Wait() })
	deadline := time.Now().Add(time.Second)
	for attempts.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if attempts.Load() < 3 || !task.Running() {
		t.Fatal("renewal failure stopped subsequent scheduled retries")
	}
}

func TestCertificateFailurePreservesTheLiveCoreDuringReload(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	core := &reloadCore{}
	c := startedController(t, f, core, &conf.Options{CertConfig: &conf.CertConfig{CertMode: "file", CertDomain: "node.example.test", CertFile: filepath.Join(t.TempDir(), "missing.pem"), KeyFile: filepath.Join(t.TempDir(), "missing.key")}})
	before := core.servedPort(c.tag)
	_, beforeInfo, _ := c.state()
	node := &panel.NodeInfo{Type: "anytls", Security: panel.Tls, Common: &panel.CommonNode{ServerPort: 5555}}
	c.opMu.Lock()
	c.reloadNode(node, []panel.UserInfo{{Id: 2, Uuid: "u2"}}, true, nil)
	c.opMu.Unlock()
	if got := core.servedPort(c.tag); got != before || !c.nodeUp || !c.needsReload {
		t.Fatalf("certificate failure retired the working core: before=%d after=%d up=%v retry=%v", before, got, c.nodeUp, c.needsReload)
	}
	if len(core.limiterAtDel) != 0 {
		t.Fatal("old listener was stopped before replacement certificate validation")
	}
	if _, activeInfo, _ := c.state(); activeInfo != beforeInfo {
		t.Fatal("failed certificate preparation published the unapplied listener configuration")
	}
	if _, reject := c.limiter.CheckLimit(format.UserTag(c.tag, "u1"), "10.0.0.1", true, true); !reject {
		t.Fatal("certificate preparation failure prevented subscriber revocation on the retained listener")
	}
}

func TestTrustTunnelControllerSkipsTheGenericCertificateManager(t *testing.T) {
	f := newFakePanel(t, 0, []panel.UserInfo{{Id: 1, Uuid: "u1"}})
	limiter.Init()
	api, err := panel.New(&conf.ApiConfig{APIHost: f.srv.URL, NodeID: 1, NodeType: "trusttunnel", Key: "fictional-key", Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	// This invalid generic configuration would fail locally if used. The
	// TrustTunnel core owns its separate panel-based certificate lifecycle.
	c := NewController(&reloadCore{}, api, &conf.Options{CertConfig: &conf.CertConfig{CertMode: "http"}})
	if err := c.Start(); err != nil {
		t.Fatal("controller attempted generic TrustTunnel certificate work:", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if c.renewCertPeriodic != nil {
		t.Fatal("duplicate TrustTunnel renewal loop started")
	}
}
