package mihomo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PoriyaVali/V2bX/common/tlscert"
	A "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	H "github.com/metacubex/mihomo/listener/http"
	I "github.com/metacubex/mihomo/listener/inbound"
	MTLS "github.com/metacubex/tls"
)

type managedServer struct {
	sockets *socketFactory
	inbound C.InboundListener
	start   func(C.Tunnel) (server, error)
	running server
	// update replaces the users of the running listener in place. It is nil
	// for protocols whose SDK authentication table is fixed when it starts.
	update func(map[string]*user) error
}

func (s *managedServer) Listen(n *node) error {
	n.mu.Lock()
	t := &nodeTunnel{node: n, generation: n.generation}
	n.mu.Unlock()
	if s.inbound != nil {
		return s.inbound.Listen(t)
	}
	var e error
	s.running, e = s.start(t)
	return e
}
func (s *managedServer) Close() error {
	var e error
	if s.inbound != nil {
		e = s.inbound.Close()
	}
	if s.running != nil {
		e = s.running.Close()
	}
	s.sockets.Close()
	return e
}

// liveAuth authenticates HTTP and SOCKS clients against a table that membership
// changes replace while the listener runs. Every request and handshake reads
// the current table.
type liveAuth struct {
	table atomic.Pointer[map[string]string]
}

func newLiveAuth(users map[string]*user) *liveAuth { a := &liveAuth{}; a.set(users); return a }
func (a *liveAuth) set(users map[string]*user) {
	table := passwords(users)
	a.table.Store(&table)
}
func (a *liveAuth) Verify(u, p string) bool { v, ok := (*a.table.Load())[u]; return ok && v == p }
func (a *liveAuth) Users() []string {
	table := *a.table.Load()
	out := make([]string, 0, len(table))
	for k := range table {
		out = append(out, k)
	}
	return out
}
func passwords(users map[string]*user) map[string]string {
	out := make(map[string]string, len(users))
	for name, u := range users {
		out[name] = u.password
	}
	return out
}

type fixedStore struct{ a auth.Authenticator }

func (s *fixedStore) Authenticator() auth.Authenticator { return s.a }
func (*fixedStore) SetAuthenticator(auth.Authenticator) {
	panic("immutable server authentication store")
}

func (n *node) buildServer(users map[string]*user) (*managedServer, error) {
	sock := newSocketFactory()
	s := &managedServer{sockets: sock}
	ip := n.options.ListenIP
	if ip == "" {
		ip = "::"
	}
	if net.ParseIP(ip) == nil {
		return nil, errors.New("ListenIP must be an IP address")
	}
	base := I.BaseOption{NameStr: n.tag, Listen: ip, Port: strconv.Itoa(n.info.Common.ServerPort), ListenConfigForAPI: sock}
	cert, key := "", ""
	if n.info.Security == 2 {
		return nil, errors.New("mihomo managed server does not yet translate panel REALITY settings")
	}
	if n.info.Security == 1 {
		if n.options.CertConfig == nil {
			return nil, errors.New("mihomo TLS server requires CertConfig")
		}
		cert, key = n.options.CertConfig.CertFile, n.options.CertConfig.KeyFile
		if cert == "" || key == "" {
			return nil, errors.New("mihomo TLS server requires server certificate and key paths")
		}
		loader, e := tlscert.NewForDomain(cert, key, n.options.CertConfig.CertDomain, time.Second)
		if e != nil {
			return nil, fmt.Errorf("mihomo server certificate: %w", e)
		}
		sock.certificate = loader
	}
	sock.certPath, sock.keyPath = cert, key
	// A validation-only listener is never bound. Nonempty placeholder users let
	// SDK validation run before the existing listener has to be closed.
	actual := users
	if len(actual) == 0 {
		actual = map[string]*user{"validation": {id: 1, uuid: "d7407d92-d2ec-4faa-94df-e93f715b7fbc", name: "validation", password: "validation"}}
	}
	switch n.info.Type {
	case "http":
		addr := net.JoinHostPort(ip, base.Port)
		a := newLiveAuth(users)
		s.start = func(t C.Tunnel) (server, error) {
			return H.NewWithConfig(LC.AuthServer{Enable: true, Listen: addr, AuthStore: &fixedStore{a: a}, Certificate: cert, PrivateKey: key}, sock, t, A.WithInName(n.tag))
		}
		s.update = func(users map[string]*user) error { a.set(users); return nil }
	case "socks5":
		a := newLiveAuth(users)
		s.start = func(t C.Tunnel) (server, error) { return n.startSOCKS(sock, t, a, cert, key) }
		s.update = func(users map[string]*user) error { a.set(users); return nil }
	case "mieru":
		if n.info.Mihomo == nil {
			return nil, errors.New("missing mieru server settings")
		}
		if n.info.Security != 0 {
			return nil, errors.New("mieru does not use a TLS server certificate")
		}
		transport := n.info.Mihomo.Transport
		if transport == "" {
			transport = "TCP"
		}
		in, e := I.NewMieru(&I.MieruOption{BaseOption: base, Transport: transport, Users: passwords(actual), TrafficPattern: n.info.Mihomo.TrafficPattern})
		if e != nil {
			return nil, e
		}
		s.inbound = in
		s.update = func(users map[string]*user) error { return in.UpdateUsers(passwords(users)) }
	case "shadowquic":
		if n.info.Mihomo == nil {
			return nil, errors.New("missing shadowquic settings")
		}
		opt := n.options.MihomoOptions
		if opt == nil || opt.JLSUpstream.Addr == "" {
			return nil, errors.New("shadowquic requires MihomoOptions.JLSUpstream.Addr (a real QUIC decoy)")
		}
		if _, _, e := net.SplitHostPort(opt.JLSUpstream.Addr); e != nil {
			return nil, errors.New("invalid ShadowQUIC JLS upstream address")
		}
		m := n.info.Mihomo
		in, e := I.NewShadowQuic(&I.ShadowQuicOption{BaseOption: base, Users: shadowQuicUsers(actual), PacketDialer: func(ctx context.Context, network, address string) (net.PacketConn, net.Addr, error) {
			return n.decoyDial(ctx, sock, network, address)
		}, JLSUpstream: I.ShadowQuicJLSUpstream{Addr: opt.JLSUpstream.Addr, SNI: opt.JLSUpstream.SNI}, ALPN: m.ALPN, QUICVersions: m.QUICVersions, ZeroRTT: m.ZeroRTT, CWND: m.CWND, BBRProfile: m.BBRProfile, ReceiveWindowConn: m.ReceiveWindowConn, ReceiveWindow: m.ReceiveWindow, DisableMTUDiscovery: m.DisableMTUDiscovery, MaxDatagramFrameSize: m.MaxDatagramFrameSize, CongestionController: m.CongestionController, Up: m.Up, Down: m.Down})
		if e != nil {
			return nil, e
		}
		s.inbound = in
		s.update = func(users map[string]*user) error { return in.UpdateUsers(shadowQuicUsers(users)) }
	case "vmess", "vless":
		v := n.info.VAllss
		if v == nil {
			return nil, errors.New("missing VMess/VLESS settings")
		}
		path, service, e := transportOptions(v.Network, v.NetworkSettings)
		if e != nil {
			return nil, e
		}
		if v.TlsSettings.Ech != "" || v.Encryption != "" {
			return nil, errors.New("panel ECH/VLESS encryption translation is not supported by the mihomo core")
		}
		if n.info.Type == "vmess" {
			var u []I.VmessUser
			for name, v := range actual {
				u = append(u, I.VmessUser{Username: name, UUID: v.uuid})
			}
			s.inbound, e = I.NewVmess(&I.VmessOption{BaseOption: base, Users: u, Certificate: cert, PrivateKey: key, WsPath: path, GrpcServiceName: service})
		} else {
			var u []I.VlessUser
			for name, u0 := range actual {
				u = append(u, I.VlessUser{Username: name, UUID: u0.uuid, Flow: v.Flow})
			}
			s.inbound, e = I.NewVless(&I.VlessOption{BaseOption: base, AllowInsecure: n.info.Security == 0, Users: u, Certificate: cert, PrivateKey: key, WsPath: path, GrpcServiceName: service})
		}
		if e != nil {
			return nil, e
		}
	case "trojan":
		if n.info.Trojan == nil {
			return nil, errors.New("missing trojan settings")
		}
		path, service, e := transportOptions(n.info.Trojan.Network, n.info.Trojan.NetworkSettings)
		if e != nil {
			return nil, e
		}
		var u []I.TrojanUser
		for name, v := range actual {
			u = append(u, I.TrojanUser{Username: name, Password: v.password})
		}
		s.inbound, e = I.NewTrojan(&I.TrojanOption{BaseOption: base, Users: u, Certificate: cert, PrivateKey: key, WsPath: path, GrpcServiceName: service})
		if e != nil {
			return nil, e
		}
	case "anytls":
		if n.info.AnyTls == nil {
			return nil, errors.New("missing AnyTLS settings")
		}
		if n.info.AnyTls.TlsSettings.Ech != "" {
			return nil, errors.New("panel AnyTLS ECH translation is not supported")
		}
		u := map[string]string{}
		for name, v := range actual {
			u[name] = v.password
		}
		var e error
		s.inbound, e = I.NewAnyTLS(&I.AnyTLSOption{BaseOption: base, Users: u, Certificate: cert, PrivateKey: key, PaddingScheme: strings.Join(n.info.AnyTls.PaddingScheme, "\n")})
		if e != nil {
			return nil, e
		}
	case "hysteria2":
		v := n.info.Hysteria2
		if v == nil {
			return nil, errors.New("missing Hysteria2 settings")
		}
		u := map[string]string{}
		for name, v := range actual {
			u[name] = v.password
		}
		var e error
		s.inbound, e = I.NewHysteria2(&I.Hysteria2Option{BaseOption: base, Users: u, Certificate: cert, PrivateKey: key, Obfs: v.ObfsType, ObfsPassword: v.ObfsPassword, IgnoreClientBandwidth: v.Ignore_Client_Bandwidth, Up: bandwidth(v.UpMbps), Down: bandwidth(v.DownMbps)})
		if e != nil {
			return nil, e
		}
	case "tuic":
		v := n.info.Tuic
		if v == nil {
			return nil, errors.New("missing TUIC settings")
		}
		u := map[string]string{}
		for _, v := range actual {
			u[v.uuid] = v.password
		}
		var e error
		s.inbound, e = I.NewTuic(&I.TuicOption{BaseOption: base, Allow0RTT: &v.ZeroRTTHandshake, Users: u, Certificate: cert, PrivateKey: key, CongestionController: v.CongestionControl})
		if e != nil {
			return nil, e
		}
	case "trusttunnel":
		var u I.AuthUsers
		for name, v := range actual {
			u = append(u, I.AuthUser{Username: name, Password: v.password})
		}
		var e error
		s.inbound, e = I.NewTrustTunnel(&I.TrustTunnelOption{BaseOption: base, Users: u, Certificate: cert, PrivateKey: key, Network: []string{"tcp", "udp"}})
		if e != nil {
			return nil, e
		}
	default:
		return nil, errors.New("unsupported mihomo server protocol")
	}
	return s, nil
}
func shadowQuicUsers(users map[string]*user) []I.ShadowQuicUser {
	out := make([]I.ShadowQuicUser, 0, len(users))
	for name, v := range users {
		out = append(out, I.ShadowQuicUser{Username: name, Password: v.password})
	}
	return out
}
func bandwidth(mbps int) string {
	if mbps == 0 {
		return ""
	}
	return strconv.Itoa(mbps) + " mbps"
}
func transportOptions(network string, raw json.RawMessage) (path, service string, err error) {
	switch network {
	case "", "tcp":
		return
	case "ws", "grpc":
		var v struct {
			Path    string `json:"path"`
			Service string `json:"serviceName"`
			Host    string `json:"host"`
		}
		if len(raw) > 0 {
			if err = json.Unmarshal(raw, &v); err != nil {
				return
			}
		}
		if network == "ws" {
			path = v.Path
			if path == "" {
				path = "/"
			}
		} else {
			service = v.Service
			if service == "" {
				err = errors.New("gRPC serviceName is required")
			}
		}
		return
	default:
		err = fmt.Errorf("mihomo managed server transport %q is unsupported", network)
		return
	}
}

// socketFactory owns accepted sockets as well as listening sockets, including
// clients still in a TLS/protocol handshake when the node is retired.
type socketFactory struct {
	certPath, keyPath string
	certificate       *tlscert.Loader
	mu                sync.Mutex
	closed            bool
	items             map[ioCloser]struct{}
}
type ioCloser interface{ Close() error }

func newSocketFactory() *socketFactory { return &socketFactory{items: map[ioCloser]struct{}{}} }
func (s *socketFactory) add(c ioCloser) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = c.Close()
		return false
	}
	s.items[c] = struct{}{}
	s.mu.Unlock()
	return true
}
func (s *socketFactory) remove(c ioCloser) { s.mu.Lock(); delete(s.items, c); s.mu.Unlock() }
func (s *socketFactory) Close() {
	s.mu.Lock()
	s.closed = true
	items := make([]ioCloser, 0, len(s.items))
	for c := range s.items {
		items = append(items, c)
	}
	s.mu.Unlock()
	for _, c := range items {
		_ = c.Close()
	}
}
func (s *socketFactory) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, e := new(net.ListenConfig).Listen(ctx, network, address)
	if e != nil {
		return nil, e
	}
	t := &trackedListener{Listener: l, owner: s}
	if !s.add(t) {
		return nil, net.ErrClosed
	}
	return t, nil
}
func (s *socketFactory) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	c, e := new(net.ListenConfig).ListenPacket(ctx, network, address)
	if e != nil {
		return nil, e
	}
	t := &trackedPacket{PacketConn: c, owner: s}
	if !s.add(t) {
		return nil, net.ErrClosed
	}
	return t, nil
}

type trackedListener struct {
	net.Listener
	owner *socketFactory
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	t := &trackedConn{Conn: c, owner: l.owner}
	if !l.owner.add(t) {
		return nil, net.ErrClosed
	}
	return t, nil
}
func (l *trackedListener) Close() error { e := l.Listener.Close(); l.owner.remove(l); return e }

type trackedConn struct {
	net.Conn
	owner *socketFactory
}

func (c *trackedConn) Close() error  { e := c.Conn.Close(); c.owner.remove(c); return e }
func (c *trackedConn) Upstream() any { return c.Conn }

func (c *trackedConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}

type trackedPacket struct {
	net.PacketConn
	owner *socketFactory
}

func (c *trackedPacket) Close() error { e := c.PacketConn.Close(); c.owner.remove(c); return e }

// Decoy packets are node infrastructure, kept outside the user traffic ledger.
// Only the configured JLS endpoint can be reached through this callback.
func (n *node) decoyDial(ctx context.Context, sockets *socketFactory, network, address string) (net.PacketConn, net.Addr, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, nil, errors.New("JLS requires UDP")
	}
	if n.options.MihomoOptions == nil || address != n.options.MihomoOptions.JLSUpstream.Addr {
		return nil, nil, errors.New("unexpected JLS endpoint")
	}
	m := &C.Metadata{}
	if e := m.SetRemoteAddress(address); e != nil {
		return nil, nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(n.config.DialTimeout)*time.Second)
	defer cancel()
	remote, e := n.destination(ctx, m)
	if e != nil {
		return nil, nil, e
	}
	addr, e := net.ResolveUDPAddr(network, remote)
	if e != nil {
		return nil, nil, e
	}
	local := n.options.SendIP
	if local == "" {
		if addr.IP.To4() != nil {
			local = "0.0.0.0"
		} else {
			local = "::"
		}
	}
	pc, e := sockets.ListenPacket(ctx, network, net.JoinHostPort(local, "0"))
	if e != nil {
		return nil, nil, e
	}
	return pc, addr, nil
}

// The host authorizes only its configured server key pair. Keep renewal scoped
// to this node and return immutable certificates to concurrent handshakes.
func (s *socketFactory) TLSKeyPairLoader(certPath, keyPath string) (func() (*MTLS.Certificate, error), error) {
	if certPath != s.certPath || keyPath != s.keyPath || certPath == "" || keyPath == "" || s.certificate == nil {
		return nil, errors.New("unconfigured server certificate path")
	}
	return func() (*MTLS.Certificate, error) {
		pair, e := s.certificate.GetCertificate(nil)
		if e != nil {
			return nil, e
		}
		return &MTLS.Certificate{Certificate: pair.Certificate, PrivateKey: pair.PrivateKey,
			OCSPStaple: pair.OCSPStaple, SignedCertificateTimestamps: pair.SignedCertificateTimestamps, Leaf: pair.Leaf}, nil
	}, nil
}
