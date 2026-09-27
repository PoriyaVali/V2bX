package hy2

import (
	"sync"
	"sync/atomic"

	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/apernet/hysteria/core/v2/server"
	"go.uber.org/zap"
)

var _ server.TrafficLogger = (*HookServer)(nil)

type HookServer struct {
	Tag     string
	logger  *zap.Logger
	Counter sync.Map
	// reportMin is the node's ReportMinTraffic in bytes. Atomic: a reload
	// sets it while the report goroutine reads it.
	reportMin atomic.Int64
	// auth is the running node's user set. A connection whose user has been
	// removed is ended at its next traffic log - hysteria checks users only at
	// the handshake, so without this a removed user kept an open connection
	// for as long as they cared to.
	auth atomic.Pointer[V2bX]
}

func (h *HookServer) TraceStream(stream server.HyStream, stats *server.StreamStats) {
}

func (h *HookServer) UntraceStream(stream server.HyStream) {
}

func (h *HookServer) LogTraffic(id string, tx, rx uint64) (ok bool) {
	if a := h.auth.Load(); a != nil && a.uid(id) == 0 {
		return false
	}

	limiterinfo, err := limiter.GetLimiter(h.Tag)
	if err != nil {
		h.logger.Error("Get limiter error", zap.String("tag", h.Tag), zap.Error(err))
		return false
	}

	userLimit, ok := limiterinfo.UserLimitInfo.Load(format.UserTag(h.Tag, id))
	if ok {
		// Atomic test-and-clear: the flag is set from the connection loggers on
		// other goroutines, so read-then-write would be a lost update.
		if userLimit.(*limiter.UserLimitInfo).OverLimit.Swap(false) {
			return false
		}
	}

	// LoadOrStore: two first connections on a fresh node each stored their
	// own counter with Load-then-Store, and the traffic counted into the one
	// overwritten was never reported.
	c, _ := h.Counter.LoadOrStore(h.Tag, counter.NewTrafficCounter())
	tc := c.(*counter.TrafficCounter)
	tc.Rx(id, int(rx))
	tc.Tx(id, int(tx))
	return true
}

func (s *HookServer) LogOnlineState(id string, online bool) {
}
