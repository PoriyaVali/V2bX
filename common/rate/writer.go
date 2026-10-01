package rate

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type Writer struct {
	writer  buf.Writer
	limiter Waiter
}

func NewRateLimitWriter(writer buf.Writer, limiter Waiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.limiter.Wait(int64(mb.Len()))
	return w.writer.WriteMultiBuffer(mb)
}
