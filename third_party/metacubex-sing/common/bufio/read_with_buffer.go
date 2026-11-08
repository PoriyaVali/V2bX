package bufio

import (
	"io"

	"github.com/metacubex/sing/common/buf"
	N "github.com/metacubex/sing/common/network"
)

type readWithBufferReader interface {
	ReadWithBuffer(getBuffer func(sizeHint int) []byte) (int, error)
}

var _ N.ReadWaiter = (*readWithBufferWaiter)(nil)

type readWithBufferWaiter struct {
	reader  readWithBufferReader
	options N.ReadWaitOptions

	// buffer is set only while ReadWithBuffer is executing.
	buffer *buf.Buffer
	// Created once during initialization so reads reuse the callback.
	bufferForRead func(int) []byte
}

func createReadWithBufferWaiter(reader any) (*readWithBufferWaiter, bool) {
	source, ok := reader.(readWithBufferReader)
	if !ok {
		return nil, false
	}
	return &readWithBufferWaiter{reader: source}, true
}

func (w *readWithBufferWaiter) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	w.options = options
	w.buffer = nil
	w.bufferForRead = func(sizeHint int) []byte {
		w.buffer = w.options.NewBuffer()
		return w.buffer.FreeBytes() // This slice starts after FrontHeadroom and ends before the reserved RearHeadroom.
	}
	return false // The returned buffer already satisfies the requested headroom.
}

func (w *readWithBufferWaiter) WaitReadBuffer() (buffer *buf.Buffer, err error) {
	n, err := w.reader.ReadWithBuffer(w.bufferForRead)

	buffer = w.buffer
	w.buffer = nil

	// If data is available, must return data with a nil error and report EOF/terminal errors on a later call.
	if n > 0 && buffer != nil {
		buffer.Truncate(n)
		w.options.PostReturn(buffer)
		return buffer, nil
	}

	// ReadWaiter callers expect a nil buffer whenever an error is returned.
	if buffer != nil {
		buffer.Release()
	}
	if err != nil {
		return nil, err
	}
	// A nil error with no data is normalized to EOF so callers never receive (nil, nil).
	return nil, io.EOF
}
