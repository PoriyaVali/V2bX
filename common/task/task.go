package task

import (
	"runtime/debug"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const minInterval = time.Minute

type Task struct {
	Interval time.Duration
	Execute  func() error
	access   sync.Mutex
	execute  sync.Mutex
	running  bool
	stop     chan struct{}
	done     chan struct{}
	wake     chan struct{}
	loops    map[chan struct{}]struct{}
}

func (t *Task) interval() time.Duration {
	t.access.Lock()
	defer t.access.Unlock()
	if t.Interval <= 0 {
		return minInterval
	}
	return t.Interval
}

func (t *Task) Start(first bool) error {
	t.access.Lock()
	if t.running {
		t.access.Unlock()
		return nil
	}
	t.running = true
	stop := make(chan struct{})
	done := make(chan struct{})
	wake := make(chan struct{}, 1)
	t.stop, t.done, t.wake = stop, done, wake
	if t.loops == nil {
		t.loops = make(map[chan struct{}]struct{})
	}
	t.loops[done] = struct{}{}
	t.access.Unlock()

	go func() {
		defer func() {
			t.access.Lock()
			delete(t.loops, done)
			close(done)
			t.access.Unlock()
		}()
		if first {
			if err := t.run(stop); err != nil {
				t.halt(stop)
				return
			}
		}

		for {
			timer := time.NewTimer(t.interval())
			select {
			case <-timer.C:
			case <-wake:
				timer.Stop()
				continue
			case <-stop:
				timer.Stop()
				return
			}
			if err := t.run(stop); err != nil {
				t.halt(stop)
				return
			}
		}
	}()
	return nil
}

func (t *Task) halt(stop chan struct{}) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.stop == stop && t.running {
		t.running = false
		close(stop)
	}
}

func (t *Task) Close() {
	t.access.Lock()
	if t.running {
		t.running = false
		close(t.stop)
	}
	t.access.Unlock()
}

// Wait joins every loop present at the call, including an older loop whose
// Execute was still running when the task restarted. Call Close first.
func (t *Task) Wait() {
	t.access.Lock()
	done := make([]chan struct{}, 0, len(t.loops))
	for ch := range t.loops {
		done = append(done, ch)
	}
	t.access.Unlock()
	for _, ch := range done {
		<-ch
	}
}

func (t *Task) Running() bool {
	t.access.Lock()
	defer t.access.Unlock()
	return t.running
}

func (t *Task) SetInterval(d time.Duration) {
	t.access.Lock()
	t.Interval = d
	if t.wake != nil {
		select {
		case t.wake <- struct{}{}:
		default:
		}
	}
	t.access.Unlock()
}

// run serializes execution across generations. A loop stopped while waiting
// for the previous Execute must not execute once it acquires the lock.
func (t *Task) run(stop <-chan struct{}) (err error) {
	t.execute.Lock()
	defer t.execute.Unlock()
	select {
	case <-stop:
		return nil
	default:
	}
	defer func() {
		if r := recover(); r != nil {
			log.WithField("stack", string(debug.Stack())).Error("task panicked; continuing at the next interval: ", r)
			err = nil
		}
	}()
	return t.Execute()
}
