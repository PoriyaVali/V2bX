package dispatcher

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type finalPayloadReader struct {
	mb buf.MultiBuffer
}

func (r *finalPayloadReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.mb
	r.mb = nil
	return mb, io.EOF
}

func (r *finalPayloadReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

func finalPayload() buf.MultiBuffer {
	b := buf.New()
	_, _ = b.Write([]byte("last payload"))
	return buf.MultiBuffer{b}
}

func TestCounterReaderPreservesPayloadWithEOF(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		var count atomic.Int64
		r := &CounterReader{Reader: &finalPayloadReader{mb: finalPayload()}, Counter: &count}
		var mb buf.MultiBuffer
		var err error
		if timeout {
			mb, err = r.ReadMultiBufferTimeout(time.Second)
		} else {
			mb, err = r.ReadMultiBuffer()
		}
		if !errors.Is(err, io.EOF) || mb.Len() != int32(len("last payload")) || count.Load() != int64(len("last payload")) {
			t.Errorf("timeout=%v: EOF discarded final payload or its counter: len=%d bytes=%d err=%v", timeout, mb.Len(), count.Load(), err)
		}
		buf.ReleaseMulti(mb)
	}
}

func TestSniffCachePreservesPayloadWithEOF(t *testing.T) {
	r := &cachedReader{reader: &finalPayloadReader{mb: finalPayload()}}
	b := buf.New()
	defer b.Release()
	if err := r.Cache(b, time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("Cache error = %v, want EOF", err)
	}
	if string(b.Bytes()) != "last payload" {
		t.Errorf("sniff buffer lost the final payload: %q", b.Bytes())
	}
	mb, err := r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || mb.Len() != int32(len("last payload")) {
		t.Fatalf("cached payload was not passed to outbound: len=%d err=%v", mb.Len(), err)
	}
}
