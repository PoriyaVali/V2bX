package task

import (
	"log"
	"sync/atomic"
	"testing"
	"time"
)

func TestTask(t *testing.T) {
	ts := Task{Execute: func() error {
		log.Println("q")
		return nil
	}, Interval: time.Second}
	ts.Start(false)
}

func TestWaitJoinsExecutingTask(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var finished atomic.Bool
	task := &Task{Interval: time.Millisecond, Execute: func() error {
		close(started)
		<-release
		finished.Store(true)
		return nil
	}}
	if err := task.Start(true); err != nil {
		t.Fatal(err)
	}
	<-started
	task.Close()
	done := make(chan struct{})
	go func() { task.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("Wait returned while Execute was still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after Execute finished")
	}
	if !finished.Load() {
		t.Fatal("Execute did not finish")
	}
}
