package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	log "github.com/sirupsen/logrus"
)

// A REALITY node reaches its borrowed site during every client's handshake:
// it relays the ClientHello there and shapes its own answer on the reply. So
// a target the node cannot reach fails every user, a target that does not
// speak TLS 1.3 with X25519 cannot be borrowed at all, and a far one adds its
// round trip to each new connection - on top of whatever the user's own link
// costs. None of that showed anywhere until users complained.

// slowRealityTarget is a handshake time from the node that is worth telling
// the operator about: past it, the target is costing users noticeably.
const slowRealityTarget = 500 * time.Millisecond

// realityTarget is the borrowed site of a REALITY node, from the panel's data.
func realityTarget(node *panel.NodeInfo) (host, port, serverName string, ok bool) {
	if node == nil || node.Security != panel.Reality {
		return "", "", "", false
	}
	var ts panel.TlsSettings
	switch {
	case node.VAllss != nil:
		ts = node.VAllss.TlsSettings
	case node.AnyTls != nil:
		ts = node.AnyTls.TlsSettings
	default:
		return "", "", "", false
	}
	host, port, serverName = ts.Dest, ts.ServerPort, ts.ServerName
	if host == "" {
		host = serverName
	}
	if port == "" {
		port = "443"
	}
	return host, port, serverName, host != "" && serverName != ""
}

type realityProbe struct {
	elapsed time.Duration
	// err: the target cannot be used - unreachable, or no TLS 1.3 with X25519.
	err error
	// certErr: usable, but its certificate does not cover the server name, so
	// a prober that compares the two sees a borrowed site that does not fit.
	certErr error
}

// probeRealityTarget does what the node does for each handshake: connect to
// the target and complete TLS 1.3 with X25519 under the node's server name.
// roots nil means the system's.
func probeRealityTarget(ctx context.Context, host, port, serverName string, roots *x509.CertPool) realityProbe {
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return realityProbe{err: fmt.Errorf("connect: %w", err)}
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tc := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519},
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true, // checked below, separately from usability
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return realityProbe{err: fmt.Errorf("TLS 1.3 with X25519: %w", err)}
	}
	p := realityProbe{elapsed: time.Since(start)}
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		p.certErr = errors.New("no certificate")
		return p
	}
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, p.certErr = state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName: serverName, Roots: roots, Intermediates: inter,
	})
	return p
}

// checkRealityTarget probes a REALITY node's target in the background and
// logs what it finds. The node starts regardless: this is a diagnosis.
func checkRealityTarget(tag string, node *panel.NodeInfo) {
	host, port, serverName, ok := realityTarget(node)
	if !ok {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		p := probeRealityTarget(ctx, host, port, serverName, nil)
		entry := log.WithFields(log.Fields{"tag": tag, "target": net.JoinHostPort(host, port), "server_name": serverName})
		switch {
		case p.err != nil:
			entry.WithField("err", p.err).Error("REALITY target cannot be borrowed from this node: every REALITY handshake here will fail")
			return
		case p.certErr != nil:
			entry.WithField("err", p.certErr).Warn("REALITY target's certificate does not cover the server name: a prober comparing them sees a borrowed site that does not fit")
		}
		if p.elapsed > slowRealityTarget {
			entry.WithField("handshake", p.elapsed.Round(time.Millisecond)).Warn("REALITY target is slow from this node and every new connection waits for it; a target in the node's own network or region shortens each handshake")
		} else {
			entry.WithField("handshake", p.elapsed.Round(time.Millisecond)).Info("REALITY target reachable")
		}
	}()
}
