package mihomo

import (
	"testing"
	"time"

	mlog "github.com/metacubex/mihomo/log"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestParseLogLevelSpellings(t *testing.T) {
	for level, want := range map[string]mlog.LogLevel{
		"": mlog.WARNING, "warn": mlog.WARNING, "warning": mlog.WARNING, "info": mlog.INFO,
		"DEBUG": mlog.DEBUG, "error": mlog.ERROR, "none": mlog.SILENT,
	} {
		got, err := parseLogLevel(level)
		assert.NoError(t, err, level)
		assert.Equal(t, want, got, level)
	}
	got, err := parseLogLevel("loud")
	assert.Error(t, err)
	assert.Equal(t, mlog.WARNING, got)
}

// A flood of one kind of line is cut to the limit; the next window's first
// line says how many were dropped.
func TestBurstLimiterCountsWhatItDrops(t *testing.T) {
	b := newBurstLimiter(time.Minute, 2)
	now := time.Unix(1000, 0)
	key := burstKey("Sudoku[a] suspicious handshake from 1.2.3.4:5: replay")
	assert.Equal(t, key, burstKey("Sudoku[a] suspicious handshake from 5.6.7.8:9: unknown user"))
	for i, allowed := range []bool{true, true, false, false, false} {
		_, ok := b.allow(key, now.Add(time.Duration(i)*time.Second))
		assert.Equal(t, allowed, ok, i)
	}
	_, ok := b.allow("another kind", now)
	assert.True(t, ok, "other lines keep their own budget")
	dropped, ok := b.allow(key, now.Add(time.Minute))
	assert.True(t, ok)
	assert.Equal(t, 3, dropped)
}

// Connection lines follow the Mihomo core's Log.Level, not V2bX's: at warn a
// refused user is not logged, at info it is.
func TestConnectionLinesFollowTheCoresLevel(t *testing.T) {
	saved := forwardLevel.Load()
	defer forwardLevel.Store(saved)
	hook := test.NewGlobal()
	defer hook.Reset()
	n := &node{tag: "core-level"}
	refused := refusedError{uid: 7, reason: "device limit (1) reached"}

	forwardLevel.Store(int32(mlog.WARNING))
	n.logAdmission(refused, "203.0.113.1", "tcp")
	assert.Empty(t, hook.AllEntries(), "refused user logged at core level warn")

	forwardLevel.Store(int32(mlog.INFO))
	n.logAdmission(refused, "203.0.113.2", "tcp")
	if assert.Len(t, hook.AllEntries(), 1) {
		entry := hook.LastEntry()
		assert.Equal(t, 7, entry.Data["uid"])
		assert.Contains(t, entry.Message, "device limit")
	}

	forwardLevel.Store(int32(mlog.SILENT))
	n.logAdmission(refused, "203.0.113.3", "tcp")
	assert.Len(t, hook.AllEntries(), 1, "core level none logs nothing")
}
