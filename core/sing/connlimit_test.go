package sing

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
)

type nopCloser struct{ _ int } // not zero-size: distinct pointers must be distinct map keys

func (nopCloser) Close() error { return nil }

// One user may hold up to the cap; the next connection is refused, and a
// freed slot is usable again.
func TestRegister_ConnCap(t *testing.T) {
	h := &HookServer{}
	var releases []func()
	for i := 0; i < 3; i++ {
		rel, res := h.register("in|u1", &nopCloser{}, 3)
		if res != registered {
			t.Fatalf("connection %d refused under the cap", i+1)
		}
		releases = append(releases, rel)
	}
	if _, res := h.register("in|u1", &nopCloser{}, 3); res != tooManyConns {
		t.Fatalf("4th connection over a cap of 3: %v", res)
	}
	// Another user is unaffected.
	if _, res := h.register("in|u2", &nopCloser{}, 3); res != registered {
		t.Fatal("a different user was refused")
	}
	releases[0]()
	if _, res := h.register("in|u1", &nopCloser{}, 3); res != registered {
		t.Fatal("a freed slot was not reusable")
	}
	// 0 = no cap.
	for i := 0; i < 50; i++ {
		if _, res := h.register("in|u3", io.Closer(&nopCloser{}), 0); res != registered {
			t.Fatal("refused with no cap")
		}
	}
}

func TestMaxConnsPerUser(t *testing.T) {
	cases := map[int]int{0: conf.DefaultConnLimit, -1: 0, 50: 50}
	for in, want := range cases {
		l := conf.LimitConfig{ConnLimit: in}
		if got := l.MaxConnsPerUser(); got != want {
			t.Errorf("ConnLimit %d -> %d, want %d", in, got, want)
		}
	}
}

func TestLogEvery(t *testing.T) {
	// logGate is process-wide, so keys unique to this run: with fixed ones a
	// second run in the same process (-count=2) found them already used.
	k, other := fmt.Sprintf("k-test-%d", time.Now().UnixNano()), fmt.Sprintf("k-other-%d", time.Now().UnixNano())
	if !logEvery(k, time.Minute) {
		t.Fatal("first line suppressed")
	}
	if logEvery(k, time.Minute) {
		t.Fatal("second line within the interval not suppressed")
	}
	if !logEvery(other, time.Minute) {
		t.Fatal("a different key was suppressed")
	}
}
