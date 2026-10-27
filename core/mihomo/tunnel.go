package mihomo

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/common/rate"
	"github.com/PoriyaVali/V2bX/limiter"
	C "github.com/metacubex/mihomo/constant"
)

type nodeTunnel struct {
	*node
	generation uint64
}

func (t *nodeTunnel) HandleTCPConn(c net.Conn, m *C.Metadata) { t.handleTCP(c, m, t.generation) }
func (t *nodeTunnel) HandleUDPPacket(p C.UDPPacket, m *C.Metadata) {
	if m == nil {
		p.Drop()
		return
	}
	t.mu.Lock()
	stale := t.closed || t.reloading || t.generation != t.node.generation
	if stale {
		t.mu.Unlock()
		p.Drop()
		return
	}
	select {
	case t.packets <- udpJob{packet: p, metadata: *m, generation: t.generation}:
	default:
		p.Drop()
	}
	t.mu.Unlock()
}

var _ C.Tunnel = (*nodeTunnel)(nil)

func (n *node) admit(m *C.Metadata, generation uint64, source string) (*flow, *counter.TrafficStorage, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.reloading || generation != n.generation {
		return nil, nil, net.ErrClosed
	}
	u := n.users[m.InUser]
	if u == nil {
		return nil, nil, errors.New("unauthorized inbound identity")
	}
	userTag := format.UserTag(n.tag, u.uuid)
	unique := map[string]bool{}
	count := 0
	for f := range n.flows {
		if f.user == u {
			unique[f.source] = true
			if !f.control {
				count++
			}
		}
	}
	if v, ok := n.limiter.UserLimitInfo.Load(userTag); ok {
		limit := v.(*limiter.UserLimitInfo).DeviceLimit.Load()
		if limit > 0 && !unique[source] && int64(len(unique)) >= limit {
			return nil, nil, errors.New("local device limit")
		}
	}
	if n.limiter.MaxConns > 0 && count >= n.limiter.MaxConns {
		return nil, nil, errors.New("connection limit")
	}
	if _, reject := n.limiter.CheckLimit(userTag, source, m.NetWork == C.TCP, true); reject {
		return nil, nil, errors.New("user device limit")
	}
	ctx, cancel := context.WithCancel(n.ctx)
	f := &flow{user: u, source: source, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	n.flows[f] = struct{}{}
	s := u.devices[source]
	if s == nil {
		s = &counter.TrafficStorage{}
		u.devices[source] = s
	}
	return f, s, nil
}
func (n *node) finish(f *flow) {
	f.close()
	n.mu.Lock()
	delete(n.flows, f)
	n.mu.Unlock()
	if f.onFinish != nil {
		f.onFinish()
	}
	close(f.done)
}
func (n *node) dialer(network string) (*net.Dialer, error) {
	d := &net.Dialer{Timeout: time.Duration(n.config.DialTimeout) * time.Second}
	if ip := n.options.SendIP; ip != "" {
		addr := net.ParseIP(ip)
		if addr == nil {
			return nil, errors.New("SendIP must be an IP address")
		}
		if network == "tcp" {
			d.LocalAddr = &net.TCPAddr{IP: addr}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: addr}
		}
	}
	return d, nil
}
func (n *node) destination(ctx context.Context, m *C.Metadata) (string, error) {
	if !m.Valid() || m.DstPort == 0 {
		return "", errors.New("invalid destination")
	}
	host := m.String()
	if n.limiter.CheckDomainRule(host) {
		return "", errors.New("blocked domain")
	}
	if blocked, _ := n.limiter.CheckDestinationRule(host, m.DstPort); blocked {
		return "", errors.New("blocked destination")
	}
	var ips []netip.Addr
	if m.Host != "" {
		var e error
		ips, e = net.DefaultResolver.LookupNetIP(ctx, "ip", m.Host)
		if e != nil {
			return "", e
		}
	} else {
		ips = []netip.Addr{m.DstIP}
	}
	// Dial the address we checked, avoiding a second DNS lookup/rebinding gap.
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		if !n.config.AllowPrivateDestinations && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast()) {
			continue
		}
		if blocked, _ := n.limiter.CheckDestinationRule(ip.String(), m.DstPort); blocked {
			continue
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(m.DstPort))), nil
	}
	return "", errors.New("no permitted destination address")
}
func sourceIP(m *C.Metadata, c net.Conn) (string, error) {
	if m.SrcIP.IsValid() {
		return m.SrcIP.Unmap().String(), nil
	}
	if c != nil {
		host, _, e := net.SplitHostPort(c.RemoteAddr().String())
		if e == nil {
			if ip, e := netip.ParseAddr(host); e == nil {
				return ip.Unmap().String(), nil
			}
		}
	}
	return "", errors.New("missing client source address")
}
func (n *node) handleTCP(client net.Conn, m *C.Metadata, generation uint64) {
	defer client.Close()
	if m == nil {
		return
	}
	source, e := sourceIP(m, client)
	if e != nil {
		return
	}
	f, device, e := n.admit(m, generation, source)
	if e != nil {
		return
	}
	defer n.finish(f)
	if !f.attach(client) {
		return
	}
	ctx, cancel := context.WithTimeout(f.ctx, time.Duration(n.config.DialTimeout)*time.Second)
	defer cancel()
	addr, e := n.destination(ctx, m)
	if e != nil {
		return
	}
	d, e := n.dialer("tcp")
	if e != nil {
		return
	}
	remote, e := d.DialContext(ctx, "tcp", addr)
	if e != nil {
		return
	}
	if !f.attach(remote) {
		return
	}
	limited := rate.NewConnRateLimiter(client, n.limiter.RateLimiter(format.UserTag(n.tag, f.user.uuid)))
	if !f.attach(limited) {
		return
	}
	metered := counter.NewConnCounter(limited, &f.user.traffic, device)
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(remote, metered)
		if err != nil || !closeWrite(remote) {
			f.close()
		}
		close(done)
	}()
	_, err := io.Copy(metered, remote)
	if err != nil || !closeWrite(client) {
		f.close()
	}
	<-done
}

// A TCP FIN ends one direction. Keep the other direction alive for protocols
// that expose half-close, including servers that respond only after request EOF.
// Never unwrap a multiplexed connection to close its shared transport.
func closeWrite(c net.Conn) bool {
	if writer, ok := c.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite() == nil
	}
	return false
}

type packetAddress struct{ network, address string }

func packetEndpoint(addr net.Addr) packetAddress {
	if addr == nil {
		return packetAddress{}
	}
	return packetAddress{addr.Network(), addr.String()}
}

type udpKey struct {
	generation      uint64
	user            string
	source, inbound packetAddress
	destination     string
}

type udpFlow struct {
	*flow
	key     udpKey
	conn    net.Conn
	packet  C.UDPPacket // retained until reader stops; owns the reply association
	device  *counter.TrafficStorage
	limiter *rate.LiveLimiter
	send    chan []byte
}

func (n *node) udpWorker() {
	defer n.workers.Done()
	for {
		select {
		case <-n.ctx.Done():
			for {
				select {
				case j := <-n.packets:
					j.packet.Drop()
				default:
					return
				}
			}
		case j := <-n.packets:
			n.sendUDP(j)
		}
	}
}
func (n *node) sendUDP(j udpJob) {
	m, p := &j.metadata, j.packet
	size := int64(len(p.Data()))
	if n.queuedBytes.Add(size) > 16*1024*1024 {
		n.queuedBytes.Add(-size)
		p.Drop()
		return
	}
	owned := true
	defer func() {
		if owned {
			n.queuedBytes.Add(-size)
		}
	}()
	payload := append([]byte(nil), p.Data()...)
	source, e := sourceIP(m, nil)
	if e != nil {
		p.Drop()
		return
	}
	// SDK packet addresses carry logical session IDs; the IP metadata alone
	// collapses separate UDP-over-stream connections into the same NAT entry.
	key := udpKey{generation: j.generation, user: m.InUser, source: packetEndpoint(p.LocalAddr()), destination: m.RemoteAddress()}
	if p.LocalAddr() == nil {
		key.source = packetAddress{address: m.SourceAddress()}
	}
	if inbound, ok := p.(C.UDPPacketInAddr); ok {
		key.inbound = packetEndpoint(inbound.InAddr())
	}
	n.mu.Lock()
	uf := n.udp[key]
	valid := !n.closed && !n.reloading && j.generation == n.generation
	n.mu.Unlock()
	if !valid {
		p.Drop()
		return
	}
	retained := false
	if uf == nil {
		f, device, e := n.admit(m, j.generation, source)
		if e != nil {
			p.Drop()
			return
		}
		ctx, cancel := context.WithTimeout(f.ctx, time.Duration(n.config.DialTimeout)*time.Second)
		addr, e := n.destination(ctx, m)
		if e != nil {
			cancel()
			p.Drop()
			n.finish(f)
			return
		}
		d, e := n.dialer("udp")
		if e != nil {
			cancel()
			p.Drop()
			n.finish(f)
			return
		}
		c, e := d.DialContext(ctx, "udp", addr)
		cancel()
		if e != nil {
			p.Drop()
			n.finish(f)
			return
		}
		if !f.attach(c) {
			p.Drop()
			n.finish(f)
			return
		}
		uf = &udpFlow{flow: f, key: key, conn: c, packet: p, device: device, limiter: n.limiter.RateLimiter(format.UserTag(n.tag, f.user.uuid)), send: make(chan []byte, 64)}
		n.mu.Lock()
		if n.closed || n.reloading || j.generation != n.generation {
			n.mu.Unlock()
			p.Drop()
			n.finish(f)
			return
		}
		n.udp[key] = uf
		n.mu.Unlock()
		if owner, ok := p.(interface{ bindFlow(*flow) bool }); ok && !owner.bindFlow(f) {
			n.mu.Lock()
			delete(n.udp, key)
			n.mu.Unlock()
			p.Drop()
			n.finish(f)
			return
		}
		retained = true
		go n.runUDP(uf)
	}
	uf.mu.Lock()
	if !uf.closed {
		select {
		case uf.send <- payload:
			owned = false
		default:
		}
	}
	uf.mu.Unlock()
	if !retained {
		p.Drop()
	}
}
func (n *node) runUDP(f *udpFlow) {
	readDone := make(chan struct{})
	go func() { n.readUDP(f); f.close(); close(readDone) }()
	for {
		select {
		case <-f.ctx.Done():
			f.close()
			for draining := true; draining; {
				select {
				case payload := <-f.send:
					n.queuedBytes.Add(-int64(len(payload)))
				default:
					draining = false
				}
			}
			<-readDone
			n.mu.Lock()
			if n.udp[f.key] == f {
				delete(n.udp, f.key)
			}
			n.mu.Unlock()
			f.packet.Drop()
			n.finish(f.flow)
			return
		case payload := <-f.send:
			if e := f.limiter.WaitContext(f.ctx, int64(len(payload))); e != nil {
				n.queuedBytes.Add(-int64(len(payload)))
				f.close()
				continue
			}
			_ = f.conn.SetWriteDeadline(time.Now().Add(time.Duration(n.config.DialTimeout) * time.Second))
			count, e := f.conn.Write(payload)
			n.queuedBytes.Add(-int64(len(payload)))
			f.user.traffic.UpCounter.Add(int64(count))
			f.device.UpCounter.Add(int64(count))
			if e != nil {
				f.close()
			}
		}
	}
}
func (n *node) readUDP(f *udpFlow) {
	b := make([]byte, 65535)
	for {
		_ = f.conn.SetReadDeadline(time.Now().Add(time.Duration(n.config.UDPTimeout) * time.Second))
		count, e := f.conn.Read(b)
		if e != nil {
			return
		}
		if e = f.limiter.WaitContext(f.ctx, int64(count)); e != nil {
			return
		}
		wrote, e := f.packet.WriteBack(b[:count], f.conn.RemoteAddr())
		if e != nil {
			return
		}
		// WriteBack may return framed byte counts. Billing is application payload.
		if wrote > count {
			wrote = count
		}
		f.user.traffic.DownCounter.Add(int64(wrote))
		f.device.DownCounter.Add(int64(wrote))
	}
}
