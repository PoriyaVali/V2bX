// A wire client and local destinations for the opt-in full-stack audit.
// Read one JSON command per line; stdout contains only JSON responses.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/quic-go"
	MTLS "github.com/metacubex/tls"
	"gopkg.in/yaml.v3"
)

type command struct {
	Action    string         `json:"action"`
	ID        string         `json:"id"`
	URL       string         `json:"url"`
	Name      string         `json:"name"`
	Profile   map[string]any `json:"profile"`
	Upload    int            `json:"upload"`
	Download  int            `json:"download"`
	Address   string         `json:"address"`
	Domain    string         `json:"domain"`
	Transport string         `json:"transport"`
	ALPN      []string       `json:"alpn"`
}
type session struct {
	proxy C.Proxy
	conn  net.Conn
}

var sessions = map[string]*session{}
var tcpTarget string
var udpTarget net.Addr
var roots *x509.CertPool

func metadata(address string, udp bool) (*C.Metadata, error) {
	m := &C.Metadata{}
	if udp {
		m.NetWork = C.UDP
	}
	err := m.SetRemoteAddress(address)
	return m, err
}
func transfer(conn net.Conn, up, down int) error {
	if up < 0 || down < 0 || up > 16<<20 || down > 16<<20 {
		return fmt.Errorf("invalid transfer size")
	}
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header, uint32(up))
	binary.BigEndian.PutUint32(header[4:], uint32(down))
	if _, err := conn.Write(append(header, bytes.Repeat([]byte{0x42}, up)...)); err != nil {
		return err
	}
	out := make([]byte, down)
	if _, err := io.ReadFull(conn, out); err != nil {
		return err
	}
	if !bytes.Equal(out, bytes.Repeat([]byte{0x5a}, down)) {
		return fmt.Errorf("TCP payload mismatch")
	}
	return nil
}
func newSession(profile map[string]any, timeout time.Duration, address string) (*session, error) {
	// JSON control commands otherwise turn YAML integer scalars into float64.
	// Restore their original numeric kind before Mihomo's weak map decoder.
	for key, value := range profile {
		if n, ok := value.(float64); ok && n == float64(int64(n)) {
			profile[key] = int64(n)
		}
	}
	p, err := adapter.ParseProxy(profile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if address == "" {
		address = tcpTarget
	}
	m, _ := metadata(address, false)
	conn, err := p.DialContext(ctx, m)
	if err != nil {
		_ = p.Close()
		return nil, err
	}
	return &session{p, conn}, nil
}
func (s *session) close() { _ = s.conn.Close(); _ = s.proxy.Close() }
func execute(c command) (map[string]any, error) {
	start := time.Now()
	switch c.Action {
	case "profile":
		var body io.ReadCloser
		if strings.HasPrefix(c.URL, "file://") {
			var err error
			body, err = os.Open(strings.TrimPrefix(c.URL, "file://"))
			if err != nil {
				return nil, err
			}
		} else {
			r, err := (&http.Client{Timeout: 10 * time.Second}).Get(c.URL)
			if err != nil {
				return nil, err
			}
			if r.StatusCode != 200 {
				r.Body.Close()
				return nil, fmt.Errorf("subscription HTTP %d", r.StatusCode)
			}
			body = r.Body
		}
		defer body.Close()
		var cfg struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.NewDecoder(io.LimitReader(body, 8<<20)).Decode(&cfg); err != nil {
			return nil, err
		}
		for _, p := range cfg.Proxies {
			if p["name"] == c.Name {
				return map[string]any{"profile": p}, nil
			}
		}
		return nil, fmt.Errorf("proxy %q missing in subscription", c.Name)
	case "open", "probe":
		timeout := 8 * time.Second
		if c.Action == "probe" {
			timeout = 2 * time.Second
		}
		s, err := newSession(c.Profile, timeout, c.Address)
		if err != nil {
			return nil, err
		}
		if c.Action == "probe" {
			defer s.close()
			deadline := time.AfterFunc(3*time.Second, func() { _ = s.conn.Close() })
			defer deadline.Stop()
		} else {
			if old := sessions[c.ID]; old != nil {
				old.close()
			}
			sessions[c.ID] = s
		}
		if err = transfer(s.conn, c.Upload, c.Download); err != nil {
			return nil, err
		}
		return map[string]any{"upload": c.Upload + 8, "download": c.Download, "elapsed_ms": time.Since(start).Milliseconds()}, nil
	case "tcp":
		s := sessions[c.ID]
		if s == nil {
			return nil, fmt.Errorf("unknown session")
		}
		if err := transfer(s.conn, c.Upload, c.Download); err != nil {
			return nil, err
		}
		return map[string]any{"upload": c.Upload + 8, "download": c.Download, "elapsed_ms": time.Since(start).Milliseconds()}, nil
	case "udp":
		s := sessions[c.ID]
		if s == nil {
			return nil, fmt.Errorf("unknown session")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		m, _ := metadata(udpTarget.String(), true)
		pc, err := s.proxy.ListenPacketContext(ctx, m)
		if err != nil {
			return nil, err
		}
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(8 * time.Second))
		if c.Upload < 0 || c.Upload > 60000 || c.Download < 0 || c.Download > 60000 {
			return nil, fmt.Errorf("invalid UDP size")
		}
		payload := make([]byte, 4+c.Upload)
		binary.BigEndian.PutUint32(payload, uint32(c.Download))
		copy(payload[4:], bytes.Repeat([]byte{0x42}, c.Upload))
		if _, err = pc.WriteTo(payload, udpTarget); err != nil {
			return nil, err
		}
		out := make([]byte, 65535)
		n, _, err := pc.ReadFrom(out)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(out[:n], bytes.Repeat([]byte{0x7b}, c.Download)) {
			return nil, fmt.Errorf("UDP payload mismatch")
		}
		return map[string]any{"upload": len(payload), "download": n}, nil
	case "close":
		if s := sessions[c.ID]; s != nil {
			s.close()
			delete(sessions, c.ID)
		}
		return map[string]any{}, nil
	case "tls":
		if c.Transport == "quic" {
			alpn := c.ALPN
			if len(alpn) == 0 {
				alpn = []string{"h3"}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, c.Address, &MTLS.Config{RootCAs: roots, ServerName: c.Domain, NextProtos: alpn}, &quic.Config{})
			if err != nil {
				return nil, err
			}
			defer conn.CloseWithError(0, "")
			return map[string]any{"serial": conn.ConnectionState().TLS.PeerCertificates[0].SerialNumber.String()}, nil
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", c.Address, &tls.Config{RootCAs: roots, ServerName: c.Domain})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		return map[string]any{"serial": conn.ConnectionState().PeerCertificates[0].SerialNumber.String()}, nil
	default:
		return nil, fmt.Errorf("unknown action")
	}
}
func destinations() error {
	listenHost := "127.0.0.1"
	if os.Getenv("E2E_DEVICE_IP") != "" {
		listenHost = "0.0.0.0"
	}
	l, err := net.Listen("tcp", net.JoinHostPort(listenHost, "0"))
	if err != nil {
		return err
	}
	tcpTarget = l.Addr().String()
	if ip := os.Getenv("E2E_DEVICE_IP"); ip != "" {
		tcpTarget = net.JoinHostPort(ip, fmt.Sprint(l.Addr().(*net.TCPAddr).Port))
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					var h [8]byte
					if _, err := io.ReadFull(conn, h[:]); err != nil {
						return
					}
					up, down := binary.BigEndian.Uint32(h[:4]), binary.BigEndian.Uint32(h[4:])
					if up > 16<<20 || down > 16<<20 {
						return
					}
					if _, err := io.CopyN(io.Discard, conn, int64(up)); err != nil {
						return
					}
					if _, err := conn.Write(bytes.Repeat([]byte{0x5a}, int(down))); err != nil {
						return
					}
				}
			}()
		}
	}()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(listenHost, "0"))
	if err != nil {
		return err
	}
	udpTarget = pc.LocalAddr()
	if ip := os.Getenv("E2E_DEVICE_IP"); ip != "" {
		udpTarget = &net.UDPAddr{IP: net.ParseIP(ip), Port: pc.LocalAddr().(*net.UDPAddr).Port}
	}
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			if n < 4 {
				continue
			}
			down := binary.BigEndian.Uint32(b[:4])
			if down <= 60000 {
				_, _ = pc.WriteTo(bytes.Repeat([]byte{0x7b}, int(down)), a)
			}
		}
	}()
	return nil
}
func main() {
	if len(os.Args) != 4 {
		panic("usage: client CA.pem decoy.pem decoy.key")
	}
	if os.Getenv("E2E_DEVICE_IP") != "" {
		// The standalone SDK has no loaded client configuration. Supply the
		// laboratory's DNS record, matching the container's hosts mapping.
		tree := trie.New[resolver.HostValue]()
		value, err := resolver.NewHostValue([]string{"172.28.90.1"})
		if err != nil {
			panic(err)
		}
		if err = tree.Insert("node.e2e.test", value); err != nil {
			panic(err)
		}
		resolver.DefaultHosts = resolver.NewHosts(tree)
	}
	pem, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err = ca.AddCertificate(string(pem)); err != nil {
		panic(err)
	}
	roots = x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	if err = destinations(); err != nil {
		panic(err)
	}
	pair, err := MTLS.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		panic(err)
	}
	listenHost := "127.0.0.1"
	if os.Getenv("E2E_DEVICE_IP") != "" {
		listenHost = "0.0.0.0"
	}
	decoy, err := quic.ListenAddr(net.JoinHostPort(listenHost, "0"), &MTLS.Config{Certificates: []MTLS.Certificate{pair}, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			conn, err := decoy.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-conn.Context().Done() }()
		}
	}()
	// The web site a Snell node's ShadowTLS v3 relays handshakes to: TLS 1.3
	// with the decoy certificate, which names node.e2e.test.
	site, err := MTLS.Listen("tcp", net.JoinHostPort(listenHost, "0"), &MTLS.Config{Certificates: []MTLS.Certificate{pair}, MinVersion: MTLS.VersionTLS13})
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			conn, err := site.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				if conn.(*MTLS.Conn).Handshake() == nil {
					_, _ = io.Copy(io.Discard, conn)
				}
			}()
		}
	}()
	enc := json.NewEncoder(os.Stdout)
	decoyAddress, siteAddress := decoy.Addr().String(), site.Addr().String()
	if ip := os.Getenv("E2E_DEVICE_IP"); ip != "" {
		decoyAddress = net.JoinHostPort(ip, fmt.Sprint(decoy.Addr().(*net.UDPAddr).Port))
		siteAddress = net.JoinHostPort(ip, fmt.Sprint(site.Addr().(*net.TCPAddr).Port))
	}
	_ = enc.Encode(map[string]any{"ready": true, "tcp_target": tcpTarget, "udp_target": udpTarget.String(), "decoy": decoyAddress, "handshake": siteAddress})
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 2<<20)
	for scan.Scan() {
		var c command
		err := json.Unmarshal(scan.Bytes(), &c)
		var result map[string]any
		if err == nil {
			result, err = execute(c)
		}
		if result == nil {
			result = map[string]any{}
		}
		result["ok"] = err == nil
		if err != nil {
			result["error"] = err.Error()
		}
		_ = enc.Encode(result)
	}
	for _, s := range sessions {
		s.close()
	}
}
