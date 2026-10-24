package trusttunnel

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
)

func TestStartupSyncReplayedOnlyForReadyProcess(t *testing.T) {
	cmd := &exec.Cmd{Process: &os.Process{Pid: 1}}
	n := &node{dir: t.TempDir(), cmd: cmd, users: map[string]string{"first-user": "first-user"}}
	if err := n.applyUsers(); err != nil {
		t.Fatal(err)
	}
	// Simulate a second sync before readiness; only its latest snapshot should
	// be used when startup finishes, even if startup already read the old file.
	n.mu.Lock()
	n.users = map[string]string{"latest-user": "latest-user"}
	n.mu.Unlock()
	if err := n.applyUsers(); err != nil {
		t.Fatal(err)
	}
	signals := 0
	signal := func() error {
		signals++
		contents, err := os.ReadFile(filepath.Join(n.dir, "credentials.toml"))
		if err != nil || !strings.Contains(string(contents), "latest-user") || strings.Contains(string(contents), "first-user") {
			t.Fatalf("reload did not see the latest complete snapshot: %v", err)
		}
		return nil
	}
	if err := n.finishReadiness(&exec.Cmd{}, signal); err != nil || n.ready || signals != 0 {
		t.Fatal("an obsolete process made its replacement ready")
	}
	if err := n.finishReadiness(cmd, signal); err != nil || !n.ready || n.pendingReload || signals != 1 {
		t.Fatalf("pending initial sync was not replayed exactly once: %v, signals=%d", err, signals)
	}
	if err := n.finishReadiness(cmd, signal); err != nil || signals != 1 {
		t.Fatal("readiness replayed an already delivered snapshot")
	}
}

func TestReadinessFailureAndShutdownPreservePendingReload(t *testing.T) {
	for _, closing := range []bool{false, true} {
		t.Run(map[bool]string{false: "signal failure", true: "shutdown"}[closing], func(t *testing.T) {
			cmd := &exec.Cmd{}
			n := &node{cmd: cmd, pendingReload: true, closing: closing}
			wantErr := errors.New("signal failed")
			calls := 0
			err := n.finishReadiness(cmd, func() error { calls++; return wantErr })
			if closing {
				if err != nil || calls != 0 || n.ready {
					t.Fatal("shutdown accepted a late readiness response")
				}
			} else if !errors.Is(err, wantErr) || calls != 1 {
				t.Fatalf("signal failure was swallowed: %v", err)
			}
			if !n.pendingReload {
				t.Fatal("undelivered reload was discarded")
			}
		})
	}
}

func TestEmptyUsersReplaceStaleCredentialsWithUnadvertisedSecret(t *testing.T) {
	n := &node{dir: t.TempDir(), users: map[string]string{}}
	path := filepath.Join(n.dir, "credentials.toml")
	if err := os.WriteFile(path, []byte("placeholder:placeholder\nstale-user"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n.writeCredentials(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil || strings.Count(string(first), "[[client]]") != 1 || !strings.Contains(string(first), "v2bx-bootstrap") || strings.Contains(string(first), "placeholder") || strings.Contains(string(first), "stale-user") {
		t.Fatalf("empty-user snapshot is not an authenticated bootstrap: %v", err)
	}
	if err := n.writeCredentials(); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) == string(second) {
		t.Fatal("bootstrap secret was reused")
	}
	entries, err := filepath.Glob(filepath.Join(n.dir, ".credentials-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary credentials were left on disk")
	}
}

func TestStartReplacesStaleCredentialsBeforeEvenAttemptingLaunch(t *testing.T) {
	n := &node{dir: t.TempDir(), users: map[string]string{}}
	path := filepath.Join(n.dir, "credentials.toml")
	if err := os.WriteFile(path, []byte("placeholder:placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := n.start(filepath.Join(n.dir, "nonexistent-endpoint")); err == nil {
		t.Fatal("missing endpoint unexpectedly started")
	}
	contents, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(contents), "placeholder") || !strings.Contains(string(contents), "v2bx-bootstrap") {
		t.Fatalf("old credentials survived up to process launch: %v", err)
	}
}

func TestInvalidUserSyncDoesNotPoisonExistingSnapshot(t *testing.T) {
	for _, uuid := range []string{"", "bad\rvalue", "bad\x00value", "bad\tvalue", `bad"value`, `bad\value`, " padded", "padded ", "bad\xffvalue", "bad\u200bvalue"} {
		t.Run(uuid, func(t *testing.T) {
			n := &node{dir: t.TempDir(), users: map[string]string{"existing": "existing"}}
			tt := &TrustTunnel{nodes: map[string]*node{"a": n}, usersMap: map[string]map[string]int{"a": {"existing": 1}}}
			if _, err := tt.AddUsers(&vCore.AddUsersParams{Tag: "a", Users: []panel.UserInfo{{Id: 2, Uuid: uuid}}}); err == nil {
				t.Fatal("invalid credential accepted")
			}
			if len(n.users) != 1 || len(tt.usersMap["a"]) != 1 || n.users["existing"] != "existing" {
				t.Fatal("failed sync poisoned existing state")
			}
		})
	}
}

func TestCertificatePublicationQueuesReloadAndRejectsObsoleteLifecycle(t *testing.T) {
	cmd := &exec.Cmd{Process: &os.Process{Pid: 1}}
	n := &node{cmd: cmd}
	commits := 0
	if err := n.applyCertificateUpdate(func() error { commits++; return nil }); err != nil || commits != 1 || !n.pendingReload {
		t.Fatal("pre-readiness certificate update was lost")
	}
	signals := 0
	if err := n.finishReadiness(cmd, func() error { signals++; return nil }); err != nil || signals != 1 || n.pendingReload {
		t.Fatal("certificate reload did not replay at readiness")
	}
	n.closing = true
	if err := n.applyCertificateUpdate(func() error { commits++; return nil }); !errors.Is(err, errClosing) || commits != 1 {
		t.Fatal("obsolete certificate lifecycle published after shutdown")
	}
}
