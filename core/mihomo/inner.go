package mihomo

import (
	"context"
	"net"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/time/rate"
)

// A listener reaches node infrastructure on its own through the tunnel, as a
// C.INNER connection: the ShadowTLS v3 handshake server of a Snell node, the
// cover site a Sudoku node hands probers to. No user owns such a connection.

// innerBudget bytes pass freely in each direction; a handshake needs a few
// KiB. After it, a stranger relayed to the endpoint is held to innerRate
// bytes a second, so the node's address cannot carry bulk traffic for them.
var (
	innerBudget int64 = 4 << 20
	innerRate         = rate.Limit(64 << 10)
)

// innerAddress is the form C.Metadata gives an address that a listener dials
// through inner.HandleTcp.
func innerAddress(address string) (string, error) {
	m := &C.Metadata{}
	if e := m.SetRemoteAddress(address); e != nil {
		return "", e
	}
	return m.RemoteAddress(), nil
}

// relayInner connects a listener's own connection to the endpoint the node
// configured for it. It stays outside the traffic ledger, the panel's rules
// and the private-destination policy, which govern users; nothing but the
// configured endpoints can be reached this way.
func (t *nodeTunnel) relayInner(client net.Conn, m *C.Metadata) {
	defer client.Close()
	address := m.RemoteAddress()
	if !t.inner[address] {
		return
	}
	d, e := t.dialer("tcp")
	if e != nil {
		return
	}
	ctx, cancel := context.WithTimeout(t.ctx, time.Duration(t.config.DialTimeout)*time.Second)
	remote, e := d.DialContext(ctx, "tcp", address)
	cancel()
	if e != nil {
		return
	}
	defer remote.Close()
	stop := context.AfterFunc(t.ctx, func() { _ = client.Close(); _ = remote.Close() })
	defer stop()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		copyInner(t.ctx, remote, client)
	}()
	copyInner(t.ctx, client, remote)
	wg.Wait()
}

// copyInner copies src to dst within innerBudget and innerRate, then ends
// dst's write side, or the whole connection when it has none.
func copyInner(ctx context.Context, dst, src net.Conn) {
	const chunk = 16 << 10
	limit := rate.NewLimiter(innerRate, chunk)
	buf := make([]byte, chunk)
	var sent int64
	for {
		n, e := src.Read(buf)
		if n > 0 {
			sent += int64(n)
			if sent > innerBudget && limit.WaitN(ctx, n) != nil {
				break
			}
			if _, we := dst.Write(buf[:n]); we != nil {
				break
			}
		}
		if e != nil {
			if closeWrite(dst) {
				return
			}
			break
		}
	}
	_ = dst.Close()
	_ = src.Close()
}
