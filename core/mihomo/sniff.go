package mihomo

import (
	"context"
	"errors"
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// The panel's protocol rules, and its domain rules for a connection made to an
// address, apply to what sniffing finds in the traffic. The sniffers and the
// timeout are those of the sing core's sniff rule, so a rule matches the same
// traffic on either core. Sniffing runs only while such a rule exists: without
// one, no connection waits for its client's first bytes.
var (
	streamSniffers = []sniff.StreamSniffer{sniff.TLSClientHello, sniff.HTTPHost, sniff.StreamDomainNameQuery, sniff.BitTorrent, sniff.SSH, sniff.RDP}
	packetSniffers = []sniff.PacketSniffer{sniff.DomainNameQuery, sniff.QUICClientHello, sniff.STUNMessage, sniff.UTP, sniff.UDPTracker, sniff.DTLSRecord, sniff.NTP}
)

// maxSniffedPackets bounds the packets a QUIC ClientHello split across
// several may take before the flow is let through unsniffed.
const maxSniffedPackets = 8

// sniffs reports whether the node's rules need the traffic to m sniffed.
// Ports of protocols where the server speaks first are never sniffed.
func (n *node) sniffs(m *C.Metadata) bool {
	protocols, domains := n.limiter.SniffedRules()
	if !protocols && (!domains || m.Host != "") {
		return false
	}
	return !sniff.Skip(&adapter.InboundContext{Destination: M.Socksaddr{Port: m.DstPort}})
}

// refuses reports whether a rule refuses what sniffing found in traffic to m.
// A domain the client asked for was checked before dialing.
func (n *node) refuses(s *adapter.InboundContext, m *C.Metadata) bool {
	if s.Protocol != "" && n.limiter.CheckProtocolRule(s.Protocol) {
		return true
	}
	if s.Domain != "" && m.Host == "" {
		refuse, _ := n.limiter.CheckDestinationRule(s.Domain, m.DstPort)
		return refuse
	}
	return false
}

// sniffTCP reads the start of a client's stream when the rules need it, and
// reports whether one refuses the connection. The connection it returns
// replays what was read.
func (n *node) sniffTCP(client net.Conn, m *C.Metadata) (net.Conn, bool) {
	if !n.sniffs(m) {
		return client, false
	}
	s := &adapter.InboundContext{}
	buffer := buf.NewPacket()
	defer buffer.Release()
	// A client that sends nothing within the timeout, or closes first, is
	// forwarded unsniffed, as the sing core forwards it.
	_ = sniff.PeekStream(context.Background(), s, client, nil, buffer, 0, streamSniffers...)
	if !buffer.IsEmpty() {
		client = &replayConn{Conn: client, pending: append([]byte(nil), buffer.Bytes()...)}
	}
	return client, n.refuses(s, m)
}

// packetSniff is what sniffing has found in a UDP flow's packets so far.
type packetSniff struct {
	adapter.InboundContext
	err     error
	packets int
}

// sniffPacket sniffs one packet of a flow still being sniffed and reports
// whether a rule refuses the flow. Only the node's UDP worker calls it, so
// nothing else touches the flow's sniffing state.
func (n *node) sniffPacket(f *udpFlow, payload []byte) bool {
	s := f.sniff
	sniffers := packetSniffers
	if errors.Is(s.err, sniff.ErrNeedMoreData) {
		// The rest of a QUIC ClientHello split across packets.
		sniffers = []sniff.PacketSniffer{sniff.QUICClientHello}
	}
	s.err = sniff.PeekPacket(context.Background(), &s.InboundContext, payload, sniffers...)
	if s.packets++; !errors.Is(s.err, sniff.ErrNeedMoreData) || s.packets >= maxSniffedPackets {
		f.sniff = nil
	}
	return n.refuses(&s.InboundContext, &f.metadata)
}

// replayConn returns the bytes sniffing read before reading the connection on.
type replayConn struct {
	net.Conn
	pending []byte
}

func (c *replayConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
func (c *replayConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}
