package task

import (
	"runtime/debug"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// minInterval stands in for an Interval that is zero or negative. Without it
// time.After(0) fires at once and the task runs back to back with no pause -
// against the panel, that is every node sending requests as fast as it can.
const minInterval = time.Minute

type Task struct {
	Interval time.Duration
	Execute  func() error
	access   sync.Mutex
	running  bool
	stop     chan struct{}
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
	// Each loop keeps the channel it was started with. It used to read t.stop
	// on every pass, so a task restarted from inside its own Execute (Close,
	// then Start - what a pull-interval change does) found the NEW channel
	// open and carried on next to the loop Start had just created.
	stop := make(chan struct{})
	t.stop = stop
	t.access.Unlock()

	go func() {
		if first {
			if err := t.run(); err != nil {
				t.halt(stop)
				return
			}
		}

		for {
			select {
			case <-time.After(t.interval()):
			case <-stop:
				return
			}

			// Closed while waiting for the timer: do not run once more.
			select {
			case <-stop:
				return
			default:
			}

			if err := t.run(); err != nil {
				t.halt(stop)
				return
			}
		}
	}()

	return nil
}

// halt stops the loop that owns stop, unless the task has since been
// restarted with a different one.
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

// SetInterval changes the pause between runs; the running loop picks it up
// from its next wait. Assigning Interval directly raced with that loop.
func (t *Task) SetInterval(d time.Duration) {
	t.access.Lock()
	t.Interval = d
	t.access.Unlock()
}

// run executes one pass and turns a panic into a logged error.
//
// Every node's periodic work runs here - pulling users, reporting traffic,
// renewing certificates - and a panic in any of it used to take the whole
// process down, and with it every node the server carries. One bad pass now
// costs that pass only; the loop carries on at the next interval.
func (t *Task) run() (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.WithField("stack", string(debug.Stack())).Error("task panicked; continuing at the next interval: ", r)
			err = nil
		}
	}()
	return t.Execute()
}
