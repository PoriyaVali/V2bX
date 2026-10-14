package tuic

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestAuthenticationUsesOneUserPasswordGeneration(t *testing.T) {
	service := &Service[string]{}
	id := [16]byte{1}
	service.UpdateUsers([]string{"first"}, [][16]byte{id}, []string{"first"})
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, name := range []string{"first", "second"} {
		workers.Add(1)
		go func(name string) {
			defer workers.Done()
			<-start
			for i := 0; i < 25000; i++ {
				service.UpdateUsers([]string{name}, [][16]byte{id}, []string{name})
			}
		}(name)
	}
	close(start)
	for i := 0; i < 100000; i++ {
		user, password, found := service.lookupUser(id)
		if !found || user != password {
			t.Errorf("mixed authentication generations: user=%q password=%q found=%v", user, password, found)
			break
		}
	}
	workers.Wait()
}

func TestConcurrentAuthenticationReservesOneAttempt(t *testing.T) {
	session := &serverSession[int]{authDone: make(chan struct{})}
	var winners atomic.Int32
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			if session.claimAuthentication() {
				winners.Add(1)
			}
		}()
	}
	close(start)
	workers.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("concurrent auth streams reserved %d attempts; duplicate success could close authDone twice", got)
	}
}
