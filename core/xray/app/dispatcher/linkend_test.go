package dispatcher

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common/buf"
)

// plainWriter is a link writer as VLESS has it under Vision or over XHTTP:
// with nothing to close.
type plainWriter struct{}

func (plainWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

// CloseAll ends each link, not only the links whose writer closes something:
// a link handed to DispatchLink ends through the hook it registers.
func TestCloseAllEndsLinksWhoseWriterDoesNotClose(t *testing.T) {
	m := &LinkManager{links: make(map[*ManagedWriter]buf.Reader)}
	ended := make(chan struct{})
	w := &ManagedWriter{writer: plainWriter{}, manager: m, end: func() { close(ended) }}
	if err := m.AddLink(w, &finalPayloadReader{}, 0); err != nil {
		t.Fatal(err)
	}
	pipe := &ManagedWriter{writer: plainWriter{}, manager: m}
	if err := m.AddLink(pipe, &finalPayloadReader{}, 0); err != nil {
		t.Fatal(err)
	}
	m.CloseAll()
	select {
	case <-ended:
	default:
		t.Fatal("the link was not ended")
	}
	if m.Len() != 0 {
		t.Fatalf("%d links left", m.Len())
	}
	if err := m.AddLink(&ManagedWriter{writer: plainWriter{}, manager: m}, &finalPayloadReader{}, 0); !errors.Is(err, errUserRemoved) {
		t.Fatalf("a removed user's new link: %v", err)
	}
}

// repeatReader gives the same payload on every read.
type repeatReader struct{ size int }

func (r repeatReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, _ = b.Write(make([]byte, r.size))
	return buf.MultiBuffer{b}, nil
}

func (r repeatReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

// What a user uploads through a DispatchLink link waits for their speed
// limit, and stops waiting when the link ends.
func TestCounterReaderHoldsUploadsToTheLimit(t *testing.T) {
	var count atomic.Int64
	// 20 kB/s with a burst of 4 kB: 12 kB take 0.4 s.
	bucket := ratelimit.NewBucketWithRate(20000, 4000)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &CounterReader{Reader: repeatReader{4000}, Counter: &count, Limiter: bucket, Context: ctx}
	start := time.Now()
	for i := 0; i < 3; i++ {
		mb, err := r.ReadMultiBuffer()
		if err != nil || mb.Len() != 4000 {
			t.Fatalf("read %d bytes, %v", mb.Len(), err)
		}
		buf.ReleaseMulti(mb)
	}
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Fatalf("12 kB at 20 kB/s took %v", took)
	}
	if count.Load() != 12000 {
		t.Fatalf("counted %d bytes", count.Load())
	}
	// The link ends while a read waits its turn.
	time.AfterFunc(50*time.Millisecond, cancel)
	slow := &CounterReader{Reader: repeatReader{8000}, Counter: &count, Limiter: ratelimit.NewBucketWithRate(10, 1), Context: ctx}
	done := make(chan error, 1)
	go func() {
		mb, err := slow.ReadMultiBufferTimeout(time.Second)
		buf.ReleaseMulti(mb)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("a read cut short by the link's end returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a read went on waiting for the limit after the link ended")
	}
}
