package dispatcher

import (
	"context"
	"fmt"
	"time"

	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// maxCheckedDestinations bounds what a UDP session remembers of the
// destinations it has checked; past it, the record starts over.
const maxCheckedDestinations = 64

// udpRuleReader applies the panel's rules to each datagram of a UDP session,
// not only to the session's first destination.
//
// A full-cone session (XUDP, which VLESS and VMess clients use for UDP,
// Trojan, Shadowsocks) carries each datagram's own destination in b.UDP, and
// freedom sends it there. routedDispatch checked the rules once, against the
// destination the session opened with: a user blocked from a port or an
// address reached it by sending one datagram somewhere allowed first. A
// datagram the rules refuse is dropped, and the session goes on. (Freedom
// checks its final rules, the private-address block among them, per
// datagram itself.)
type udpRuleReader struct {
	buf.Reader
	ctx     context.Context
	limiter *limiter.Limiter
	email   string
	first   [2]net.Destination // the session's destination, as opened and as routed
	checked map[net.Destination]bool
}

func newUDPRuleReader(ctx context.Context, reader buf.Reader, l *limiter.Limiter, email string, opened, routed net.Destination) *udpRuleReader {
	return &udpRuleReader{Reader: reader, ctx: ctx, limiter: l, email: email,
		first: [2]net.Destination{opened, routed}, checked: make(map[net.Destination]bool)}
}

func (r *udpRuleReader) permits(dest net.Destination) bool {
	if dest == r.first[0] || dest == r.first[1] {
		return true
	}
	if permitted, ok := r.checked[dest]; ok {
		return permitted
	}
	var host string
	if dest.Address.Family().IsDomain() {
		host = dest.Address.Domain()
	} else {
		host = dest.Address.IP().String()
	}
	reject, kind := r.limiter.CheckDestinationRule(host, dest.Port.Value())
	if reject {
		errors.LogError(r.ctx, fmt.Sprintf("User %s access %s %s reject by %s rule",
			r.email, dest.Network, dest.NetAddr(), kind))
	}
	if len(r.checked) >= maxCheckedDestinations {
		clear(r.checked)
	}
	r.checked[dest] = !reject
	return !reject
}

// filter drops the datagrams the rules refuse, in place.
func (r *udpRuleReader) filter(mb buf.MultiBuffer) buf.MultiBuffer {
	kept := mb[:0]
	for _, b := range mb {
		if b.UDP == nil || r.permits(*b.UDP) {
			kept = append(kept, b)
			continue
		}
		b.Release()
	}
	clear(mb[len(kept):])
	return kept
}

func (r *udpRuleReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		mb, err := r.Reader.ReadMultiBuffer()
		if mb = r.filter(mb); !mb.IsEmpty() || err != nil {
			return mb, err
		}
	}
}

// ReadMultiBufferTimeout keeps the reader a buf.TimeoutReader when the one
// it wraps is: outbounds and mux read through it with a timeout.
func (r *udpRuleReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	tr, ok := r.Reader.(buf.TimeoutReader)
	if !ok {
		return nil, buf.ErrNotTimeoutReader
	}
	deadline := time.Now().Add(timeout)
	for {
		mb, err := tr.ReadMultiBufferTimeout(time.Until(deadline))
		if mb = r.filter(mb); !mb.IsEmpty() || err != nil {
			return mb, err
		}
		if time.Until(deadline) <= 0 {
			return nil, buf.ErrReadTimeout
		}
	}
}

// Interrupt passes on, as every link reader's does: a closed session
// interrupts the pipe behind it.
func (r *udpRuleReader) Interrupt() {
	common.Interrupt(r.Reader)
}
