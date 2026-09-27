// Package sockopt answers whether this machine lets V2bX set a TCP socket
// option, before anything depends on it.
//
// Some cores fail a listen outright when a socket option is refused - xray
// does - so an option that a kernel lacks (an OpenVZ container without bbr,
// an old kernel) would take the node down instead of just going unused. Each
// answer comes from trying it once on a throwaway socket, with the
// privileges the service really runs with, and is remembered.
package sockopt

import (
	"net"
	"sync"
	"syscall"
)

var (
	mu    sync.Mutex
	known = map[string]bool{}
)

func cached(key string, try func() error) bool {
	mu.Lock()
	defer mu.Unlock()
	if ok, done := known[key]; done {
		return ok
	}
	ok := try() == nil
	known[key] = ok
	return ok
}

// Congestion reports whether name can be set as a socket's TCP congestion
// control.
func Congestion(name string) bool {
	if name == "" {
		return false
	}
	return cached("cc:"+name, func() error { return trySetString(tcpCongestion, name) })
}

// NotSentLowat reports whether TCP_NOTSENT_LOWAT can be set.
func NotSentLowat() bool {
	return cached("notsent_lowat", func() error { return trySetInt(TCPNotSentLowat, 16384) })
}

// underlyingTCP finds the socket under a connection that one or more layers
// (TLS, REALITY, a PROXY-protocol reader, a traffic counter) wrap. It follows
// the unwrap methods those layers share and stops at the first thing that
// gives access to a file descriptor. A layer that hides its connection - a
// websocket, a multiplexed stream - ends the search and nothing is found.
func underlyingTCP(c any) (rawConner, bool) {
	for i := 0; i < 16 && c != nil; i++ {
		if rc, ok := c.(rawConner); ok {
			if a, ok := c.(interface{ LocalAddr() net.Addr }); ok {
				if _, isTCP := a.LocalAddr().(*net.TCPAddr); isTCP {
					return rc, true
				}
			}
		}
		switch v := c.(type) {
		case interface{ Upstream() any }:
			c = v.Upstream()
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		case interface{ Raw() net.Conn }:
			c = v.Raw()
		default:
			return nil, false
		}
	}
	return nil, false
}

type rawConner interface {
	SyscallConn() (syscall.RawConn, error)
}

// SetNotSentLowat sets TCP_NOTSENT_LOWAT to bytes on the socket under c, if
// one can be reached. It reports whether it was set.
//
// It has to be done per connection: a listening socket's value is not passed
// on to the connections it accepts, and on the kernel this was measured on,
// accepted connections did not follow the net.ipv4.tcp_notsent_lowat sysctl
// either - only a value set on the connection itself took effect.
func SetNotSentLowat(c any, bytes int) bool {
	if bytes <= 0 {
		return false
	}
	rc, ok := underlyingTCP(c)
	if !ok {
		return false
	}
	raw, err := rc.SyscallConn()
	if err != nil {
		return false
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) { setErr = setInt(int(fd), TCPNotSentLowat, bytes) }); err != nil {
		return false
	}
	return setErr == nil
}
