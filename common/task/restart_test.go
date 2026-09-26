package task

import (
	"sync/atomic"
	"testing"
	"time"
)

// A task that restarts itself from inside Execute - which nodeInfoMonitor does
// whenever the panel changes the pull interval - must end up with ONE loop.
// The old loop used to read t.stop afresh on every pass, found the new, open
// channel and kept going, so the task then ran twice concurrently.
func TestTask_RestartFromInsideExecuteLeavesOneLoop(t *testing.T) {
	var running, maxRunning, runs atomic.Int64
	var restarted atomic.Bool
	ts := &Task{Interval: 5 * time.Millisecond}
	ts.Execute = func() error {
		n := running.Add(1)
		defer running.Add(-1)
		for {
			m := maxRunning.Load()
			if n <= m || maxRunning.CompareAndSwap(m, n) {
				break
			}
		}
		runs.Add(1)
		if restarted.CompareAndSwap(false, true) {
			ts.Close()
			_ = ts.Start(false)
		}
		time.Sleep(2 * time.Millisecond)
		return nil
	}
	_ = ts.Start(false)
	defer ts.Close()
	time.Sleep(300 * time.Millisecond)
	if got := maxRunning.Load(); got > 1 {
		t.Fatalf("task ran %d copies at once after restarting itself", got)
	}
	before := runs.Load()
	ts.Close()
	time.Sleep(50 * time.Millisecond)
	after := runs.Load()
	time.Sleep(50 * time.Millisecond)
	if runs.Load() != after {
		t.Fatalf("task kept running after Close (%d -> %d runs)", before, runs.Load())
	}
}

// A zero interval must not turn into a loop with no pause.
func TestTask_ZeroIntervalIsNotABusyLoop(t *testing.T) {
	var runs atomic.Int64
	ts := &Task{Interval: 0, Execute: func() error { runs.Add(1); return nil }}
	_ = ts.Start(false)
	time.Sleep(100 * time.Millisecond)
	ts.Close()
	if n := runs.Load(); n > 2 {
		t.Fatalf("zero interval ran %d times in 100ms", n)
	}
}
