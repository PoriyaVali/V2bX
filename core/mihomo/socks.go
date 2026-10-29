package mihomo

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	A "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	S "github.com/metacubex/mihomo/transport/socks5"
)

func (n *node) startSOCKS(sockets *socketFactory, t C.Tunnel, authenticator auth.Authenticator, cert, key string) (server, error) {
	l, e := sockets.Listen(n.ctx, "tcp", net.JoinHostPort(n.options.ListenIP, n.port()))
	if e != nil {
		return nil, e
	}
	if cert != "" {
		l = tls.NewListener(l, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: sockets.certificate.GetCertificate})
	}
	go acceptLoop(l, func(c net.Conn) { n.socksConn(c, sockets, t, authenticator) })
	return l, nil
}

// acceptLoop stops only when its listener is closed. A transient failure such
// as EMFILE must not leave the port bound but no longer accepting.
func acceptLoop(l net.Listener, handle func(net.Conn)) {
	var delay time.Duration
	for {
		c, e := l.Accept()
		if e != nil {
			if errors.Is(e, net.ErrClosed) {
				return
			}
			if delay = 2 * delay; delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay > time.Second {
				delay = time.Second
			}
			time.Sleep(delay)
			continue
		}
		delay = 0
		go handle(c)
	}
}
func (n *node) port() string { return strconv.Itoa(n.info.Common.ServerPort) }
func (n *node) socksConn(c net.Conn, sockets *socketFactory, t C.Tunnel, authenticator auth.Authenticator) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Duration(n.config.DialTimeout) * time.Second))
	var relay net.PacketConn
	var association *flow
	defer func() {
		if relay != nil {
			_ = relay.Close()
		}
		if association != nil {
			n.finish(association)
		}
	}()
	target, command, name, e := S.ServerHandshakeWithReply(c, authenticator, func(cmd S.Command, name string, target S.Addr) (net.Addr, error) {
		if cmd != S.CmdUDPAssociate {
			return c.LocalAddr(), nil
		}
		// The relay port belongs to this authenticated TCP association. It is never
		// the unauthenticated shared UDP port in a conventional SOCKS listener.
		nt := t.(*nodeTunnel)
		m := &C.Metadata{InUser: name, NetWork: C.UDP}
		source, e := sourceIP(m, c)
		if e != nil {
			return nil, e
		}
		m.SrcIP, _ = netip.ParseAddr(source)
		f, _, e := n.admit(m, nt.generation, source)
		if e != nil {
			return nil, e
		}
		association = f
		n.mu.Lock()
		f.control = true
		n.mu.Unlock()
		if !f.attach(c) {
			return nil, net.ErrClosed
		}
		host, _, e := net.SplitHostPort(c.LocalAddr().String())
		if e != nil {
			return nil, e
		}
		relay, e = sockets.ListenPacket(context.Background(), "udp", net.JoinHostPort(host, "0"))
		if e != nil {
			return nil, e
		}
		if !f.attach(relay) {
			return nil, net.ErrClosed
		}
		return relay.LocalAddr(), nil
	})
	if e != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	if command == S.CmdConnect {
		t.HandleTCPConn(A.NewSocket(target, c, C.SOCKS5, A.WithInUser(name)))
		return
	}
	if command != S.CmdUDPAssociate || relay == nil {
		return
	}
	// Close the relay and all of its forwarding flows when the control channel
	// ends. TCP source IP and first UDP source port are pinned server-side.
	owner := &associationOwner{alive: true}
	defer owner.close()
	remoteHost, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	remoteIP, _ := netip.ParseAddr(remoteHost)
	pinnedPort := 0
	// RFC 1928 clients name the address they will send from, or all zeros.
	// Clients behind NAT and older sing-based clients name another address
	// (the latter their first destination). Pin a requested port only when the
	// request names this client's own address; otherwise pin the first datagram.
	if requested := target.UDPAddr(); requested != nil {
		if ip, ok := netip.AddrFromSlice(requested.IP); ok && ip.Unmap() == remoteIP.Unmap() {
			pinnedPort = requested.Port
		}
	}
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		b := make([]byte, 65535)
		for {
			count, addr, e := relay.ReadFrom(b)
			if e != nil {
				return
			}
			source, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(source.IP)
			if !ok || ip.Unmap() != remoteIP.Unmap() {
				continue
			}
			if pinnedPort == 0 {
				pinnedPort = source.Port
			}
			if source.Port != pinnedPort {
				continue
			}
			dst, payload, e := S.DecodeUDPPacket(b[:count])
			if e != nil {
				continue
			}
			p := &socksPacket{conn: relay, source: addr, payload: append([]byte(nil), payload...), owner: owner}
			t.HandleUDPPacket(A.NewPacket(dst, p, C.SOCKS5, A.WithInUser(name)))
		}
	}()
	_, _ = io.Copy(io.Discard, c)
	_ = relay.Close()
	<-udpDone
}

type associationOwner struct {
	mu    sync.Mutex
	alive bool
	flows map[*flow]struct{}
}

func (a *associationOwner) add(f *flow) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.alive {
		return false
	}
	if a.flows == nil {
		a.flows = map[*flow]struct{}{}
	}
	a.flows[f] = struct{}{}
	f.onFinish = func() { a.mu.Lock(); delete(a.flows, f); a.mu.Unlock() }
	return true
}
func (a *associationOwner) close() {
	a.mu.Lock()
	a.alive = false
	var flows []*flow
	for f := range a.flows {
		flows = append(flows, f)
	}
	a.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
}

type socksPacket struct {
	conn    net.PacketConn
	source  net.Addr
	payload []byte
	owner   *associationOwner
}

func (p *socksPacket) Data() []byte        { return p.payload }
func (p *socksPacket) Drop()               { p.payload = nil }
func (p *socksPacket) LocalAddr() net.Addr { return p.source }
func (p *socksPacket) InAddr() net.Addr    { return p.conn.LocalAddr() }
func (p *socksPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	data, e := S.EncodeUDPPacket(S.ParseAddrToSocksAddr(addr), b)
	if e != nil {
		return 0, e
	}
	count, e := p.conn.WriteTo(data, p.source)
	if e != nil {
		return 0, e
	}
	if count != len(data) {
		return 0, errors.New("short SOCKS datagram write")
	}
	return len(b), nil
}
func (p *socksPacket) bindFlow(f *flow) bool { return p.owner.add(f) }
