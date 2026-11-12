package sing

import (
	"io"
	"testing"
	"time"
)

type gatedCloser struct {
	gate   chan struct{}
	closed chan struct{}
}

func (c gatedCloser) Close() error {
	<-c.gate
	close(c.closed)
	return nil
}

// One connection whose close waits does not keep a removed user's other
// connections open behind it.
func TestCloseDetachedConnsDoesNotQueueBehindASlowClose(t *testing.T) {
	slow := gatedCloser{gate: make(chan struct{}), closed: make(chan struct{})}
	open := make(chan struct{})
	close(open)
	quick := gatedCloser{gate: open, closed: make(chan struct{})}
	done := make(chan int, 1)
	go func() { done <- closeDetachedConns([]io.Closer{slow, quick}) }()
	select {
	case <-quick.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the second connection waited for the first to close")
	}
	select {
	case <-done:
		t.Fatal("returned before every connection had closed")
	case <-time.After(50 * time.Millisecond):
	}
	close(slow.gate)
	select {
	case n := <-done:
		if n != 2 {
			t.Fatalf("closed %d connections, want 2", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not return once every connection had closed")
	}
}
