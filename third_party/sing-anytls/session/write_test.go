package session

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

// slowLinkPair is a server-side connection whose peer drains about 8 KiB/s,
// with minimal socket buffers so a large write really waits on the link - a
// heavily throttled mobile path seen from the node.
func slowLinkPair(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	_ = server.(*net.TCPConn).SetWriteBuffer(4096)
	_ = client.(*net.TCPConn).SetReadBuffer(4096)
	t.Cleanup(func() { server.Close(); client.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	return server
}

// stalledLinkPair is a server-side connection whose peer never reads: a client
// that stopped reading, or a path that died with data in flight.
func stalledLinkPair(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	_ = server.(*net.TCPConn).SetWriteBuffer(4096)
	_ = client.(*net.TCPConn).SetReadBuffer(4096)
	t.Cleanup(func() { server.Close(); client.Close() })
	return server
}

// 🔴 A control frame behind a data write that can never finish must not wait
// for it forever.
//
// Data writes carry no deadline, so a slow link is never cut. When the peer
// stops reading for good, though, the data writer holds the line until the
// operating system gives up on the connection - possibly never, while the
// peer keeps advertising a zero window - and a FIN behind it, from a stream
// being closed, waited just as long.
func TestControlFrameBehindStalledWriteIsBounded(t *testing.T) {
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	s := NewServerSession(stalledLinkPair(t), nil, &pad, logger.NOP())
	defer s.Close()

	dataErr := make(chan error, 1)
	go func() {
		// Far more than the socket buffers hold.
		_, err := s.writeDataFrame(1, make([]byte, 1<<20))
		dataErr <- err
	}()
	time.Sleep(300 * time.Millisecond) // the data writer is stuck holding the line
	ctrlErr := make(chan error, 1)
	go func() {
		_, err := s.writeConnWithin([]byte{cmdFIN, 0, 0, 0, 1, 0, 0}, 500*time.Millisecond)
		ctrlErr <- err
	}()

	select {
	case err := <-ctrlErr:
		if err == nil {
			t.Fatal("a control frame reported success on a connection that stopped draining")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a control frame behind a stalled data write waited without bound")
	}
	select {
	case err := <-dataErr:
		if err == nil {
			t.Fatal("the stalled data write reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled data write was never released")
	}
	if !s.IsClosed() {
		t.Fatal("the session was left open on a connection that cannot drain")
	}
}

// drainingLinkPair is a server-side connection whose peer reads 4 KiB every
// interval, with minimal socket buffers.
func drainingLinkPair(t *testing.T, interval time.Duration) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	_ = server.(*net.TCPConn).SetWriteBuffer(4096)
	_ = client.(*net.TCPConn).SetReadBuffer(4096)
	t.Cleanup(func() { server.Close(); client.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
			time.Sleep(interval)
		}
	}()
	return server
}

// 🔴 A write that takes longer than a control frame's patience, but keeps
// moving, is a slow link, not a dead one: the session must survive it.
//
// The first bound on a control frame's wait counted only elapsed time, so a
// large write over a weak link that held the connection past it closed the
// session - every stream on it - although data was still leaving.
func TestControlFrameWaitsOutASlowButMovingWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("drains a large write over a deliberately slow link")
	}
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	// About 16 KiB/s: 96 KiB takes some six seconds, twice the patience below.
	s := NewServerSession(drainingLinkPair(t, 250*time.Millisecond), nil, &pad, logger.NOP())
	defer s.Close()

	dataErr := make(chan error, 1)
	go func() {
		_, err := s.writeDataFrame(1, make([]byte, 96<<10))
		dataErr <- err
	}()
	time.Sleep(300 * time.Millisecond) // the data writer holds the line
	ctrlErr := make(chan error, 1)
	go func() {
		_, err := s.writeConnWithin([]byte{cmdFIN, 0, 0, 0, 2, 0, 0}, 3*time.Second)
		ctrlErr <- err
	}()

	if err := <-dataErr; err != nil {
		t.Fatalf("a slow but moving data write was cut: %v", err)
	}
	if err := <-ctrlErr; err != nil {
		t.Fatalf("the control frame failed behind a slow but moving write: %v", err)
	}
	if s.IsClosed() {
		t.Fatal("the session was closed although its write kept moving")
	}
}

// 🔴 A control frame queued behind a long data write must neither cut that
// write short nor close the session.
//
// writeControlFrame set a five-second write deadline on the whole connection
// before waiting for the write lock. A data frame still draining over a slow
// link inherited that deadline and failed with a timeout, and the control
// frame, finding its deadline already spent once it got the lock, closed the
// session - every stream on it - over nothing but a slow link.
func TestControlFrameBehindSlowDataWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("drains a frame over a deliberately slow link")
	}
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	s := NewServerSession(slowLinkPair(t), nil, &pad, logger.NOP())
	defer s.Close()

	// One full data frame: well over five seconds at this rate.
	data := make([]byte, 64000)
	dataErr := make(chan error, 1)
	go func() {
		_, err := s.writeDataFrame(1, data)
		dataErr <- err
	}()
	time.Sleep(300 * time.Millisecond) // the data writer holds the line
	ctrlErr := make(chan error, 1)
	go func() {
		_, err := s.writeControlFrame(newFrame(cmdSYNACK, 2))
		ctrlErr <- err
	}()

	if err := <-dataErr; err != nil {
		t.Fatalf("a data write was cut short by a control frame's deadline: %v", err)
	}
	if err := <-ctrlErr; err != nil {
		t.Fatalf("the control frame failed behind a slow data write: %v", err)
	}
	if s.IsClosed() {
		t.Fatal("the session was closed over a slow link")
	}
}

// 🔴 A write larger than one frame must arrive as well-formed frames. It was
// sent as a single frame whose 16-bit length had wrapped, and the client lost
// the session parsing the rest as headers.
func TestLargeWriteIsSplitIntoFrames(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	s := NewServerSession(server, nil, &pad, logger.NOP())

	data := make([]byte, 200_000)
	for i := range data {
		data[i] = byte(i)
	}
	go func() { _, _ = s.writeDataFrame(7, data) }()

	var got []byte
	var hdr rawHeader
	for len(got) < len(data) {
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			t.Fatalf("after %d bytes: %v", len(got), err)
		}
		if hdr.Cmd() != cmdPSH || hdr.StreamID() != 7 {
			t.Fatalf("after %d bytes: frame cmd %d sid %d, want PSH on 7", len(got), hdr.Cmd(), hdr.StreamID())
		}
		chunk := make([]byte, hdr.Length())
		if _, err := io.ReadFull(client, chunk); err != nil {
			t.Fatal(err)
		}
		got = append(got, chunk...)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("the stream's bytes changed in transit")
	}
}
