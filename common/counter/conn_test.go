package counter

import (
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// Does the plain Read/Write path accumulate, or overwrite?
func TestConnCounterAccumulates(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	s := &TrafficStorage{}
	counted := NewConnCounter(c1, s)

	go func() {
		for i := 0; i < 3; i++ {
			c2.Write(make([]byte, 100))
		}
	}()

	buf3 := make([]byte, 100)
	total := 0
	for i := 0; i < 3; i++ {
		n, err := counted.Read(buf3)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}

	if got := s.UpCounter.Load(); got != int64(total) {
		t.Errorf("after reading %d bytes in 3 calls, UpCounter = %d (want %d)", total, got, total)
	}
}

// The buffer path, for comparison - this one is written with Add.
func TestReadBufferAccumulates(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	s := &TrafficStorage{}
	counted := NewConnCounter(c1, s).(*ConnCounter)

	go func() {
		for i := 0; i < 3; i++ {
			c2.Write(make([]byte, 100))
		}
	}()

	for i := 0; i < 3; i++ {
		b := buf.NewSize(100)
		if err := counted.ReadBuffer(b); err != nil {
			t.Fatal(err)
		}
		b.Release()
	}

	if got := s.UpCounter.Load(); got != 300 {
		t.Errorf("ReadBuffer path: UpCounter = %d (want 300)", got)
	}
}
