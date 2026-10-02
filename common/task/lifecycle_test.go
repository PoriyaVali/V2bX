package task

import (
	"sync/atomic"
	"testing"
	"time"
)

// Restarting during a blocked Execute must not overlap it, and shutdown must
// join that old generation even after the replacement has been stopped.
func TestRestartWaitsForPreviousExecution(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var runs atomic.Int64
	ts := &Task{Interval: time.Hour, Execute: func() error {
		runs.Add(1)
		entered <- struct{}{}
		<-release
		return nil
	}}
	if err := ts.Start(true); err != nil {
		t.Fatal(err)
	}
	<-entered
	ts.Close()
	if err := ts.Start(true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
		close(release)
		ts.Close()
		ts.Wait()
		t.Fatal("replacement Execute overlapped the previous generation")
	case <-time.After(30 * time.Millisecond):
	}
	ts.Close()
	done := make(chan struct{})
	go func() { ts.Wait(); close(done) }()
	select {
	case <-done:
		close(release)
		t.Fatal("Wait ignored the old in-flight Execute")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown failed to join both generations")
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("a stopped replacement executed: %d calls", got)
	}
}

func TestSetIntervalWakesSleepingTask(t *testing.T) {
	called := make(chan struct{}, 1)
	ts := &Task{Interval: time.Hour, Execute: func() error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	}}
	_ = ts.Start(false)
	defer func() { ts.Close(); ts.Wait() }()
	ts.SetInterval(time.Millisecond)
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("SetInterval left the task asleep at its previous interval")
	}
}
