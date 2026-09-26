// Package memguard keeps V2bX's memory in step with the machine it runs on.
//
// Go does not know how much RAM the VPS has. Left alone, the garbage collector
// lets the heap grow to twice what is live, and a traffic peak on a small VPS
// can take the machine into swap - everything slows down, and a restart looks
// like the cure because it throws the heap away. This package:
//
//   - reads the RAM ceiling (the cgroup limit when one is set, otherwise the
//     machine's total) and sets Go's soft memory limit to a share of it, so the
//     collector works harder as the heap nears the ceiling instead of letting
//     it run into swap or the OOM killer;
//   - watches the machine's free memory and, when it runs low, hands unused
//     heap back to the system and says so in the log;
//   - logs a periodic health line (RSS, heap, goroutines, open files), so a
//     node that degrades over hours shows WHAT grows instead of only feeling
//     slow.
package memguard

import (
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// DefaultLimitPercent is the share of the RAM ceiling V2bX aims its heap at.
// The rest is left for the kernel's socket buffers, the page cache and
// whatever else runs on the VPS.
const DefaultLimitPercent = 70

var (
	checkEvery  = 15 * time.Second
	healthEvery = 10 * time.Minute
	freeGap     = time.Minute
)

// Snapshot is one reading of the process and the machine. Zero means unknown.
type Snapshot struct {
	CeilingBytes   uint64 // RAM available to this process: cgroup limit or MemTotal
	AvailableBytes uint64 // MemAvailable (or the cgroup headroom, whichever is lower)
	RSSBytes       uint64
	HeapInuseBytes uint64
	SoftLimitBytes uint64 // Go's memory limit; 0 = none
	Goroutines     int
	OpenFiles      int
}

var (
	mu        sync.Mutex
	started   bool
	softLimit uint64
)

// Start applies the soft limit and begins watching. percent 0 means
// DefaultLimitPercent; a negative percent turns the limit off (the watcher and
// health log still run). A GOMEMLIMIT set in the environment always wins.
func Start(percent int) {
	mu.Lock()
	if started {
		mu.Unlock()
		return
	}
	started = true
	mu.Unlock()

	ceiling := ceilingBytes()
	switch {
	case os.Getenv("GOMEMLIMIT") != "":
		log.Info("memory: GOMEMLIMIT is set in the environment; leaving it as is")
	case ceiling == 0:
		log.Info("memory: RAM ceiling unknown on this system; no soft limit set")
	case percent < 0:
		log.Info("memory: soft limit disabled by config")
	default:
		if percent == 0 || percent > 95 {
			percent = DefaultLimitPercent
		}
		limit := ceiling / 100 * uint64(percent)
		debug.SetMemoryLimit(int64(limit))
		mu.Lock()
		softLimit = limit
		mu.Unlock()
		log.Infof("memory: RAM ceiling %d MiB, V2bX soft limit %d MiB (%d%%)",
			ceiling>>20, limit>>20, percent)
	}
	go watch(ceiling)
}

// Read takes a snapshot.
func Read() Snapshot {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	mu.Lock()
	sl := softLimit
	mu.Unlock()
	return Snapshot{
		CeilingBytes:   ceilingBytes(),
		AvailableBytes: availableBytes(),
		RSSBytes:       rssBytes(),
		HeapInuseBytes: ms.HeapInuse,
		SoftLimitBytes: sl,
		Goroutines:     runtime.NumGoroutine(),
		OpenFiles:      openFiles(),
	}
}

// Pressure grades how close the machine is to running out of memory.
type Pressure int

const (
	PressureNone Pressure = iota
	PressureLow           // under 10% of the ceiling free
	PressureCritical      // under 5% free
)

func pressureOf(ceiling, available uint64) Pressure {
	if ceiling == 0 || available == 0 {
		return PressureNone // unknown: never act on a guess
	}
	switch {
	case available < ceiling/20:
		return PressureCritical
	case available < ceiling/10:
		return PressureLow
	}
	return PressureNone
}

func watch(ceiling uint64) {
	var lastFree, lastHealth time.Time
	tick := time.NewTicker(checkEvery)
	defer tick.Stop()
	for now := range tick.C {
		p := pressureOf(ceiling, availableBytes())
		if p != PressureNone && now.Sub(lastFree) >= freeGap {
			lastFree = now
			before := Read()
			// Returns the heap the collector has already freed to the OS. Cheap
			// next to what swapping or an OOM kill would cost every user here.
			debug.FreeOSMemory()
			after := Read()
			entry := log.WithFields(log.Fields{
				"available_mib": after.AvailableBytes >> 20,
				"ceiling_mib":   ceiling >> 20,
				"rss_mib":       before.RSSBytes >> 20,
				"rss_after_mib": after.RSSBytes >> 20,
				"goroutines":    after.Goroutines,
			})
			if p == PressureCritical {
				entry.Error("memory: machine almost out of RAM; returned free heap to the system")
			} else {
				entry.Warn("memory: machine low on RAM; returned free heap to the system")
			}
		}
		if now.Sub(lastHealth) >= healthEvery {
			lastHealth = now
			s := Read()
			log.WithFields(log.Fields{
				"rss_mib":       s.RSSBytes >> 20,
				"heap_mib":      s.HeapInuseBytes >> 20,
				"available_mib": s.AvailableBytes >> 20,
				"goroutines":    s.Goroutines,
				"open_files":    s.OpenFiles,
			}).Info("health")
		}
	}
}
