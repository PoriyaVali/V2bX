package sing

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PoriyaVali/V2bX/common/format"
)

// Bytes counted while a report is being taken must land in that report or
// the next one - never nowhere. The reset used to be a Load and then a
// Store(0), and whatever arrived between the two was wiped unbilled.
func TestTrafficSlice_NoBytesLostUnderConcurrentReset(t *testing.T) {
	s := &Sing{
		hookServer:                &HookServer{},
		users:                     &UserMap{uidMap: map[string]int{format.UserTag("in", "u1"): 1}},
		nodeReportMinTrafficBytes: map[string]int64{},
	}
	storages := s.hookServer.trafficStorages("in", "u1", "", false)
	st := storages[0]

	const writers, perWriter, chunk = 8, 20000, 7
	var reported atomic.Int64
	stop := make(chan struct{})
	var collector sync.WaitGroup
	collector.Add(1)
	go func() {
		defer collector.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			slice, _ := s.GetUserTrafficSlice("in", true)
			for _, u := range slice {
				reported.Add(u.Upload + u.Download)
			}
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				st.UpCounter.Add(chunk)
				st.DownCounter.Add(chunk)
			}
		}()
	}
	wg.Wait()
	close(stop)
	collector.Wait()
	slice, _ := s.GetUserTrafficSlice("in", true)
	for _, u := range slice {
		reported.Add(u.Upload + u.Download)
	}
	if want := int64(writers * perWriter * chunk * 2); reported.Load() != want {
		t.Fatalf("reported %d bytes, counted %d: %d lost", reported.Load(), want, want-reported.Load())
	}
}
