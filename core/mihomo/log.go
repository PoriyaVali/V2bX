package mihomo

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mlog "github.com/metacubex/mihomo/log"
	log "github.com/sirupsen/logrus"
)

// Mihomo logs through its own package. Left alone it prints every line at
// INFO and above to the process logger, whatever the Mihomo core's Log level
// says, so its debug lines (a refused handshake) could never be turned on and
// its chatter could never be turned off. Its printing is silenced here and its
// events are forwarded instead, at the core's level and marked core=mihomo.
var (
	forwardOnce  sync.Once
	forwardLevel atomic.Int32 // an mlog.LogLevel
	bursts       = newBurstLimiter(time.Minute, 10)
)

// defaultLogLevel is the Mihomo core's level when its Log section has none:
// refused clients and failures, without a line per connection.
const defaultLogLevel = "warn"

// parseLogLevel reads a Log.Level the way the other cores spell it.
func parseLogLevel(level string) (mlog.LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "":
		return parseLogLevel(defaultLogLevel)
	case "debug", "trace":
		return mlog.DEBUG, nil
	case "info":
		return mlog.INFO, nil
	case "warn", "warning":
		return mlog.WARNING, nil
	case "error", "fatal", "panic":
		return mlog.ERROR, nil
	case "none", "silent", "off":
		return mlog.SILENT, nil
	}
	return mlog.WARNING, fmt.Errorf("unknown mihomo log level %q (use debug, info, warn, error or none)", level)
}

// setLogLevel applies the core's level and starts forwarding on first use.
// One forwarder serves the process: a config reload builds the next core
// while the previous one still runs, and two forwarders would print every
// line twice.
func setLogLevel(level mlog.LogLevel) {
	forwardLevel.Store(int32(level))
	forwardOnce.Do(func() {
		events := mlog.Subscribe()
		mlog.SetLevel(mlog.SILENT)
		go func() {
			for event := range events {
				forward(event)
			}
		}()
	})
}

func forward(event mlog.Event) {
	if event.LogLevel < mlog.LogLevel(forwardLevel.Load()) || event.LogLevel == mlog.SILENT {
		return
	}
	entry := log.WithField("core", "mihomo")
	switch event.LogLevel {
	case mlog.DEBUG:
		entry.Debug(event.Payload)
	case mlog.INFO:
		entry.Info(event.Payload)
	case mlog.WARNING:
		// A public port meets scanners all day; each probe is a warning.
		// Keep the first few of a kind each minute and count the rest.
		if suppressed, ok := bursts.allow(burstKey(event.Payload), time.Now()); ok {
			if suppressed > 0 {
				entry = entry.WithField("suppressed", suppressed)
			}
			entry.Warn(event.Payload)
		}
	case mlog.ERROR:
		entry.Error(event.Payload)
	}
}

// burstKey groups lines that differ only in the client: the text before
// " from ", so "Sudoku[a] suspicious handshake from 1.2.3.4: ..." shares a
// budget with every other refused handshake on node a.
func burstKey(payload string) string {
	if i := strings.Index(payload, " from "); i > 0 {
		return payload[:i]
	}
	if len(payload) > 64 {
		return payload[:64]
	}
	return payload
}

// burstLimiter lets limit lines of each key through per window. The first
// line let through in a new window carries the count dropped in the previous
// one, so a flood stays visible without filling the journal.
type burstLimiter struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	keys   map[string]*burst
}

type burst struct {
	start            time.Time
	seen, suppressed int
}

func newBurstLimiter(window time.Duration, limit int) *burstLimiter {
	return &burstLimiter{window: window, limit: limit, keys: map[string]*burst{}}
}

// allow reports whether a line of key may be printed now, and how many lines
// of key were dropped before it.
func (b *burstLimiter) allow(key string, now time.Time) (int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.keys[key]
	if s == nil || now.Sub(s.start) >= b.window {
		dropped := 0
		if s != nil {
			dropped = s.suppressed
		}
		if len(b.keys) >= 1024 {
			// Bounded: keys come from remote input (a payload without
			// " from "). Forgetting them only resets their budgets.
			b.keys = map[string]*burst{}
		}
		b.keys[key] = &burst{start: now, seen: 1}
		return dropped, true
	}
	s.seen++
	if s.seen > b.limit {
		s.suppressed++
		return 0, false
	}
	return 0, true
}
