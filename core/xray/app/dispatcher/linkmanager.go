package dispatcher

import (
	"errors"
	sync "sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

var (
	errUserRemoved  = errors.New("user removed")
	errTooManyLinks = errors.New("too many connections (ConnLimit)")
)

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}

// LinkManager holds the connections one user has open, so they can be closed
// the moment the user is removed and counted against ConnLimit.
type LinkManager struct {
	links  map[*ManagedWriter]buf.Reader
	mu     sync.Mutex
	closed bool // set by CloseAll; the user is gone, so nothing new is added
}

// AddLink registers a connection. It refuses one for a user already removed,
// or one that would take the user past max open connections (0 = no cap).
func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader, max int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errUserRemoved
	}
	if max > 0 && len(m.links) >= max {
		return errTooManyLinks
	}
	m.links[writer] = reader
	return nil
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.links, writer)
}

// Len is the number of connections open right now.
func (m *LinkManager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.links)
}

// CloseAll closes every connection and refuses new ones.
//
// The set is taken under the lock and closed outside it. It used to be ranged
// over with no lock at all while connections opened and closed on other
// goroutines - a concurrent map write, which Go answers by ending the process.
// Closing outside the lock matters too: Close calls RemoveWriter, which takes
// this same lock.
func (m *LinkManager) CloseAll() {
	m.mu.Lock()
	m.closed = true
	links := m.links
	m.links = make(map[*ManagedWriter]buf.Reader)
	m.mu.Unlock()
	for w, r := range links {
		common.Close(w)
		common.Interrupt(r)
	}
}
