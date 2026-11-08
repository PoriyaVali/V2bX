// Package udpecho checks UDP through a proxy against local echo servers. The
// served-node test and its separate mihomo client run the same checks.
package udpecho

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Listen starts an echo server on 127.0.0.1, which answers each datagram
// with itself. Closing the connection stops it.
func Listen() (*net.UDPConn, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return pc, nil
}

// QUICSized is the size of the datagrams QUIC, and so HTTP/3, sends.
const QUICSized = 1350

// Resends is how many times a datagram is sent before it counts as lost.
// Clients resend what gets no answer, so a lost first datagram is only noted.
const Resends = 3

// Wait is how long an answer to each datagram is waited for.
const Wait = 2 * time.Second

type answer struct {
	payload []byte
	from    net.Addr
}

// Check sends datagrams through pc, as a client of a UDP proxy does, and
// wants each answered by the server it went to:
//
//   - a short datagram to first;
//   - a QUICSized one to first, which a proxy that carries UDP in QUIC
//     datagrams has to split;
//   - a short one to second over the same session, as full-cone clients
//     send: STUN, games, and QUIC moving to another address.
//
// The notes say what was answered only once resent. Check closes pc.
func Check(pc net.PacketConn, first, second netip.AddrPort) (notes []string, err error) {
	defer pc.Close()
	answers := make(chan answer, 8)
	failed := make(chan error, 1)
	go func() {
		for {
			buf := make([]byte, 65535)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				failed <- err
				return
			}
			select {
			case answers <- answer{buf[:n], from}:
			default:
			}
		}
	}()
	quic := make([]byte, QUICSized)
	_, _ = rand.Read(quic)
	steps := []struct {
		what    string
		payload []byte
		to      netip.AddrPort
	}{
		{"a datagram", []byte("ping"), first},
		{fmt.Sprintf("a %d-byte datagram", QUICSized), quic, first},
		{"a datagram to a second server over the same session", []byte("pong"), second},
	}
	for _, step := range steps {
		sent, err := exchange(pc, answers, failed, step.payload, step.to)
		if err != nil {
			return notes, fmt.Errorf("%s: %w", step.what, err)
		}
		if sent > 1 {
			notes = append(notes, fmt.Sprintf("%s was answered only once sent %d times", step.what, sent))
		}
	}
	return notes, nil
}

// Refused checks that a node drops a datagram its rules refuse without
// ending the session: a datagram to allowed is answered; one to blocked, sent
// three times over the same session, is not; and allowed answers again. An
// answer from blocked that arrives at any point, the last exchange included,
// fails it. Refused closes pc.
func Refused(pc net.PacketConn, allowed, blocked netip.AddrPort) error {
	defer pc.Close()
	answers := make(chan answer, 8)
	failed := make(chan error, 1)
	leaked := make(chan net.Addr, 1)
	go func() {
		for {
			buf := make([]byte, 65535)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				failed <- err
				return
			}
			if Same(from, blocked) || string(buf[:n]) == "refused" {
				select {
				case leaked <- from:
				default:
				}
				continue
			}
			select {
			case answers <- answer{buf[:n], from}:
			default:
			}
		}
	}()
	if _, err := exchange(pc, answers, failed, []byte("before"), allowed); err != nil {
		return fmt.Errorf("a datagram to an allowed server: %w", err)
	}
	for i := 0; i < Resends; i++ {
		if _, err := pc.WriteTo([]byte("refused"), net.UDPAddrFromAddrPort(blocked)); err != nil {
			return fmt.Errorf("a datagram to a refused server: %w", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := exchange(pc, answers, failed, []byte("after"), allowed); err != nil {
		return fmt.Errorf("the session after a refused datagram: %w", err)
	}
	select {
	case from := <-leaked:
		return fmt.Errorf("a datagram to %v, which the rules refuse, was answered from %v", blocked, from)
	default:
		return nil
	}
}

// Bulk sends count datagrams of size random bytes to to through pc, one at a
// time, each until it is answered, as Check does. It returns the bytes sent,
// resends included, and the bytes answered, late duplicates included: what a
// node that counts datagrams should bill. Bulk closes pc.
func Bulk(pc net.PacketConn, to netip.AddrPort, count, size int) (sent, received int64, err error) {
	defer pc.Close()
	answers := make(chan answer, 64)
	failed := make(chan error, 1)
	var mu sync.Mutex
	var answered int64
	go func() {
		for {
			buf := make([]byte, 65535)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				failed <- err
				return
			}
			if !Same(from, to) {
				continue
			}
			mu.Lock()
			answered += int64(n)
			mu.Unlock()
			select {
			case answers <- answer{buf[:n], from}:
			default:
			}
		}
	}()
	total := func() int64 {
		mu.Lock()
		defer mu.Unlock()
		return answered
	}
	for i := 0; i < count; i++ {
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		times, err := exchange(pc, answers, failed, payload, to)
		sent += int64(times * size)
		if err != nil {
			return sent, total(), fmt.Errorf("datagram %d of %d: %w", i+1, count, err)
		}
	}
	time.Sleep(300 * time.Millisecond) // an answer to a resent datagram, late
	return sent, total(), nil
}

// exchange sends payload to to until it is answered, and returns how many
// times it was sent.
func exchange(pc net.PacketConn, answers <-chan answer, failed <-chan error, payload []byte, to netip.AddrPort) (int, error) {
	addr := net.UDPAddrFromAddrPort(to)
	for sent := 1; sent <= Resends; sent++ {
		if _, err := pc.WriteTo(payload, addr); err != nil {
			return sent, err
		}
		wait := time.NewTimer(Wait)
	waiting:
		for {
			select {
			case a := <-answers:
				if !bytes.Equal(a.payload, payload) {
					continue // an earlier datagram, answered late
				}
				wait.Stop()
				if !Same(a.from, to) {
					return sent, fmt.Errorf("the answer came from %v, not %v", a.from, to)
				}
				return sent, nil
			case err := <-failed:
				wait.Stop()
				return sent, err
			case <-wait.C:
				break waiting
			}
		}
	}
	return Resends, fmt.Errorf("none of %d was answered", Resends)
}

// Same is whether from, as a client reads an answer's source, is want.
func Same(from net.Addr, want netip.AddrPort) bool {
	if from == nil {
		return false
	}
	got, err := netip.ParseAddrPort(from.String())
	if err != nil {
		return false
	}
	return got.Addr().Unmap() == want.Addr().Unmap() && got.Port() == want.Port()
}

// ErrNoUDP is a client profile that leaves UDP off.
var ErrNoUDP = errors.New("the profile leaves UDP off")
