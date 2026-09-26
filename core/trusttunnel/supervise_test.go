package trusttunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a fake endpoint: with TT_FAKE_ENDPOINT=crash it
// records that it started (one line in ./starts) and exits at once.
func TestMain(m *testing.M) {
	if os.Getenv("TT_FAKE_ENDPOINT") == "crash" {
		f, _ := os.OpenFile("starts", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		f.WriteString("x\n")
		f.Close()
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func countStarts(dir string) int {
	b, _ := os.ReadFile(filepath.Join(dir, "starts"))
	return strings.Count(string(b), "\n")
}

func crashingNode(t *testing.T) (*node, string) {
	t.Helper()
	t.Setenv("TT_FAKE_ENDPOINT", "crash")
	dir := t.TempDir()
	n := &node{tag: "tt-test", dir: dir, metricsPort: 1, users: map[string]string{},
		done: make(chan struct{}), stop: make(chan struct{})}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.start(bin); err != nil {
		t.Fatal(err)
	}
	go n.supervise(bin)
	return n, dir
}

func shortBackoff(t *testing.T, min, max time.Duration) {
	t.Helper()
	oldMin, oldMax := restartMinDelay, restartMaxDelay
	restartMinDelay, restartMaxDelay = min, max
	t.Cleanup(func() { restartMinDelay, restartMaxDelay = oldMin, oldMax })
}

// An endpoint that dies at once must be restarted with a growing delay. The
// delay used to be reset right after each restart, so a crash loop relaunched
// it at the minimum interval forever.
func TestSupervise_CrashLoopBacksOff(t *testing.T) {
	shortBackoff(t, 20*time.Millisecond, 160*time.Millisecond)
	n, dir := crashingNode(t)
	time.Sleep(1500 * time.Millisecond)
	n.shutdown()
	// 20+40+80+160+160... ms plus process start-up: well under a dozen. At a
	// fixed 20 ms it is twenty or more.
	if got := countStarts(dir); got > 12 {
		t.Fatalf("%d starts in 1.5 s: the restart delay is not backing off", got)
	}
}

// Removing a node while a restart is waiting must not start another endpoint:
// nobody would stop it, and it would keep the node's port.
func TestSupervise_NoRestartAfterShutdown(t *testing.T) {
	shortBackoff(t, 400*time.Millisecond, 400*time.Millisecond)
	n, dir := crashingNode(t)
	deadline := time.Now().Add(5 * time.Second)
	for countStarts(dir) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // it has crashed and is now waiting to restart
	done := make(chan struct{})
	go func() { n.shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not return while a restart was pending")
	}
	time.Sleep(800 * time.Millisecond)
	if got := countStarts(dir); got != 1 {
		t.Fatalf("endpoint started %d times; want 1 - it was restarted after the node was removed", got)
	}
}
