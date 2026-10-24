package trusttunnel

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/internal/certtest"
)

func TestCertificateSnapshotsRejectClientOnlyAndUnknownUsage(t *testing.T) {
	ca := certtest.NewAuthority(t)
	now := time.Now()
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	first := ca.Issue(t, "rotation.test", 1, now.Add(-time.Hour), now.Add(time.Hour))
	certtest.Write(t, cp, kp, first)
	lifecycle := &certificateLifecycle{dir: dir, hostname: "rotation.test", config: &conf.CertConfig{CertMode: "file", CertDomain: "rotation.test", CertFile: cp, KeyFile: kp}}
	active, err := lifecycle.snapshot(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []certtest.Pair{
		ca.IssueWithUsage(t, []string{"rotation.test"}, 2, now.Add(-time.Hour), now.Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}),
		ca.IssueWithUnknownUsage(t, []string{"rotation.test"}, 3, now.Add(-time.Hour), now.Add(time.Hour)),
	} {
		certtest.Write(t, cp, kp, bad)
		if _, err := lifecycle.snapshot(now); err == nil {
			t.Fatal("non-server certificate snapshot accepted")
		}
		preserved, err := os.ReadFile(active.certPath)
		if err != nil || !bytes.Equal(preserved, first.Certificate) {
			t.Fatal("rejected candidate damaged the active snapshot")
		}
	}
}
