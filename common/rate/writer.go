package rate

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type Writer struct {
	writer  buf.Writer
	limiter Waiter
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewRateLimitWriter(writer buf.Writer, limiter Waiter) buf.Writer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Writer{
		writer:  writer,
		limiter: limiter,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (w *Writer) Close() error {
	w.cancel()
	return common.Close(w.writer)
}

func (w *Writer) Interrupt() {
	w.cancel()
	_ = common.Interrupt(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := waitWithContext(w.ctx, w.limiter, int64(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}
