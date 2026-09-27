package conf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func watchRig(t *testing.T) (string, *Conf, chan struct{}) {
	t.Helper()
	old := reloadDelay
	reloadDelay = 100 * time.Millisecond
	t.Cleanup(func() { reloadDelay = old })
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeConfig(t, path, "info")
	c := New()
	if err := c.LoadFromPath(path); err != nil {
		t.Fatal(err)
	}
	reloads := make(chan struct{}, 16)
	if err := c.Watch(path, "", "", func() { reloads <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	return path, c, reloads
}

func writeConfig(t *testing.T, path, level string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"Log":{"Level":"`+level+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// replaceConfig saves the way editors and `sed -i` do: a new file renamed
// over the old one.
func replaceConfig(t *testing.T, path, level string) {
	t.Helper()
	tmp := path + ".tmp"
	writeConfig(t, tmp, level)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func expectReload(t *testing.T, reloads chan struct{}, what string) {
	t.Helper()
	select {
	case <-reloads:
	case <-time.After(5 * time.Second):
		t.Fatalf("no reload after %s", what)
	}
}

func expectNoReload(t *testing.T, reloads chan struct{}, what string) {
	t.Helper()
	select {
	case <-reloads:
		t.Fatalf("unexpected reload after %s", what)
	case <-time.After(500 * time.Millisecond):
	}
}

// 🔴 Every save is picked up, including the second and later ones made by
// renaming a new file over the config. The watch was on the file itself and
// was lost with its inode on the first such save.
func TestWatch_SeesEveryAtomicSave(t *testing.T) {
	path, c, reloads := watchRig(t)
	for i, level := range []string{"debug", "warn", "error"} {
		replaceConfig(t, path, level)
		expectReload(t, reloads, "atomic save")
		reloadMu.Lock()
		got := c.LogConfig.Level
		reloadMu.Unlock()
		if got != level {
			t.Fatalf("save %d: running config has level %q, want %q", i+1, got, level)
		}
	}
}

func TestWatch_InPlaceWrite(t *testing.T) {
	path, _, reloads := watchRig(t)
	writeConfig(t, path, "debug")
	expectReload(t, reloads, "in-place write")
}

// A burst of writes reloads once, after they stop - including writes that
// land after the first one has been seen. The old debounce dropped anything
// in the ten seconds after the first event.
func TestWatch_BurstReloadsOnceWithTheLastContent(t *testing.T) {
	path, c, reloads := watchRig(t)
	for _, level := range []string{"debug", "warn", "error"} {
		writeConfig(t, path, level)
		time.Sleep(30 * time.Millisecond)
	}
	expectReload(t, reloads, "a burst of writes")
	expectNoReload(t, reloads, "the same burst")
	reloadMu.Lock()
	defer reloadMu.Unlock()
	if c.LogConfig.Level != "error" {
		t.Fatalf("level = %q, want the last write's %q", c.LogConfig.Level, "error")
	}
}

// A broken edit is not applied, and the running config stays as it was.
func TestWatch_BrokenConfigIsNotApplied(t *testing.T) {
	path, c, reloads := watchRig(t)
	os.WriteFile(path, []byte(`{"Log":`), 0o600)
	expectNoReload(t, reloads, "a broken config")
	reloadMu.Lock()
	defer reloadMu.Unlock()
	if c.LogConfig.Level != "info" {
		t.Fatalf("level = %q after a broken edit, want the running %q", c.LogConfig.Level, "info")
	}
}

// Other files in the same directory do not trigger a reload.
func TestWatch_IgnoresOtherFiles(t *testing.T) {
	path, _, reloads := watchRig(t)
	os.WriteFile(filepath.Join(filepath.Dir(path), "cert.pem"), []byte("x"), 0o600)
	expectNoReload(t, reloads, "writing an unrelated file")
}
