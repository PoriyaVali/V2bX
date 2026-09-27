package conf

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// reloadMu serialises config reloads.
var reloadMu sync.Mutex

// reloadDelay is how long the watcher waits after the last change to a
// watched file before reloading, so a file written in several steps is read
// once it is complete. A variable so tests can shorten it.
var reloadDelay = 5 * time.Second

func (p *Conf) Watch(filePath, xDnsPath string, sDnsPath string, reload func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("new watcher error: %s", err)
	}
	// Watch the directories and pick the files out of their events. A watch on
	// a file follows its inode, and an editor or `sed -i` saves by writing a
	// new file and renaming it over the old one - the inode being watched is
	// gone, so the first such save reloaded and every later one went unseen.
	targets := make(map[string]bool) // absolute paths of the watched files
	dirs := make(map[string]bool)
	for _, path := range []string{filePath, xDnsPath, sDnsPath} {
		if path == "" {
			continue
		}
		abs, err := filepath.Abs(path)
		if err == nil {
			_, err = os.Stat(abs)
		}
		if err != nil {
			watcher.Close()
			return fmt.Errorf("watch file error: %s", err)
		}
		targets[abs] = true
		if dir := filepath.Dir(abs); !dirs[dir] {
			if err := watcher.Add(dir); err != nil {
				watcher.Close()
				return fmt.Errorf("watch file error: %s", err)
			}
			dirs[dir] = true
		}
	}
	configPath, _ := filepath.Abs(filePath)
	delay := reloadDelay

	var (
		mu            sync.Mutex
		timer         *time.Timer
		configChanged bool // since the last reload: the config itself, not only a DNS file
	)
	doReload := func() {
		mu.Lock()
		what := "DNS file"
		if configChanged {
			what = "config file"
		}
		configChanged = false
		mu.Unlock()
		// One reload at a time: a second edit arriving while the first is
		// still tearing nodes down must not interleave.
		reloadMu.Lock()
		defer reloadMu.Unlock()
		log.Printf("%s changed, reloading...", what)
		// Parse into a fresh value and only then swap it in. This used to
		// reset the live config, log a parse error and call reload() anyway -
		// so one typo in config.json tore down every node and rebuilt them
		// from an empty config, leaving the process up and serving nobody.
		next := New()
		if err := next.LoadFromPath(filePath); err != nil {
			log.Printf("reload config error, keeping the running config: %s", err)
			return
		}
		*p = *next
		reload()
		log.Println("reload config success")
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case e, ok := <-watcher.Events:
				if !ok {
					return
				}
				if e.Op == fsnotify.Chmod {
					continue
				}
				name, err := filepath.Abs(e.Name)
				if err != nil || !targets[name] {
					continue
				}
				// Reload once things go quiet. The old debounce ignored every
				// event for ten seconds after the first, so an edit made in
				// that window was never loaded.
				mu.Lock()
				if name == configPath {
					configChanged = true
				}
				if timer == nil {
					timer = time.AfterFunc(delay, doReload)
				} else {
					timer.Reset(delay)
				}
				mu.Unlock()
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				if err != nil {
					log.Printf("File watcher error: %s", err)
				}
			}
		}
	}()
	return nil
}
