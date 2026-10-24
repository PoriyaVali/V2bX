package tlscert

import (
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/internal/certtest"
)

func TestLoaderRejectsUnrelatedAndInvalidReplacementThenRecovers(t *testing.T) {
	ca := certtest.NewAuthority(t)
	now := time.Now()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	first := ca.Issue(t, "rotation.test", 1, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	certtest.Write(t, certPath, keyPath, first)
	l, err := NewForDomain(certPath, keyPath, "rotation.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []certtest.Pair{
		ca.Issue(t, "unrelated.test", 2, now.Add(-time.Hour), now.Add(90*24*time.Hour)),
		ca.Issue(t, "rotation.test", 3, now.Add(-48*time.Hour), now.Add(-time.Hour)),
		ca.Issue(t, "rotation.test", 4, now.Add(time.Hour), now.Add(90*24*time.Hour)),
		ca.IssueWithUsage(t, []string{"rotation.test"}, 6, now.Add(-time.Hour), now.Add(90*24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}),
		ca.IssueWithUnknownUsage(t, []string{"rotation.test"}, 7, now.Add(-time.Hour), now.Add(90*24*time.Hour)),
	} {
		certtest.Write(t, certPath, keyPath, candidate)
		got, err := l.GetCertificate(nil)
		if err != nil || got.Leaf.SerialNumber.Int64() != 1 {
			t.Fatalf("invalid replacement discarded last valid pair: %v", err)
		}
	}
	second := ca.Issue(t, "rotation.test", 5, now.Add(-time.Hour), now.Add(91*24*time.Hour))
	certtest.Write(t, certPath, keyPath, second)
	got, err := l.GetCertificate(nil)
	if err != nil || got.Leaf.SerialNumber.Int64() != 5 {
		t.Fatalf("did not recover with valid replacement: %v", err)
	}
	if _, err := NewForDomain(certPath, keyPath, "unrelated.test", time.Second); err == nil {
		t.Fatal("initial unrelated leaf accepted")
	}
}
