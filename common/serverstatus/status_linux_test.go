//go:build linux

package serverstatus

import (
	"sync"
	"testing"
)

// Every node runs its own status task, so these calls overlap. Under -race
// this caught the unguarded CPU sample they all share.
func TestGetSystemStatusConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := GetSystemStatus()
			if err != nil {
				t.Error(err)
				return
			}
			if s.CPU < 0 || s.CPU > 100 {
				t.Errorf("CPU = %f, want 0..100", s.CPU)
			}
		}()
	}
	wg.Wait()
}
