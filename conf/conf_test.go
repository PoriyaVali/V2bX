package conf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConf_LoadFromPath(t *testing.T) {
	c := New()
	if err := c.LoadFromPath("../example/config.json"); err != nil {
		t.Fatalf("load example config: %v", err)
	}
	if len(c.NodeConfig) == 0 {
		t.Fatal("example config parsed but yielded no nodes")
	}
}

// Watch used to be exercised by logging its error on a path that does not exist
// and then blocking on `select {}` forever, so `go test ./conf/` could only ever
// end in the 10-minute timeout — which is why the suite could not be wired into
// CI. Watch a file that actually exists and assert it registers cleanly.
func TestConf_Watch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Watch(path, "", "", func() {}); err != nil {
		t.Fatalf("watch an existing file: %v", err)
	}
}

func TestConf_WatchMissingFileErrors(t *testing.T) {
	c := New()
	if err := c.Watch(filepath.Join(t.TempDir(), "does-not-exist.json"), "", "", func() {}); err == nil {
		t.Fatal("watching a missing file should error")
	}
}
