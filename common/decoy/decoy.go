// Package decoy serves static cover sites for supported inbound fallbacks and
// HTTP masquerades. Certificate domains select a stable built-in profile;
// operators can instead supply a dedicated directory of public assets.
// Content is prepared once, and public requests have bounded concurrency and
// rate budgets independent of authenticated proxy traffic.
//
// Loopback fallbacks accept HTTP/1.1 and prior-knowledge HTTP/2. UDP nodes may
// also own a TCP HTTPS listener on their port using the node's certificate.
// Protocol integration remains the caller's responsibility: a cover page does
// not conceal an address, certificate, or TLS/QUIC fingerprint.
package decoy

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/common/tlscert"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/netutil"
)

// Site owns a loopback cover listener and, optionally, a public TLS companion.
type Site struct {
	listener    net.Listener
	server      *http.Server
	addr        string
	once        sync.Once
	mu          sync.Mutex
	closed      bool
	companion   *Site
	connections int
}

// decoyTemplate is one plausible site. Kept intentionally dull: a site with
// nothing to say attracts no follow-up.
type decoyTemplate struct {
	title    string
	tagline  string
	sections []string
	footer   string
}

var decoyTemplates = []decoyTemplate{
	{
		title:   "Aperture Notes",
		tagline: "Field notes on light, film and slow photography.",
		sections: []string{
			"On metering for shadow detail",
			"Developing at home without a darkroom",
			"Why I went back to a fixed lens",
		},
		footer: "Written irregularly. No newsletter, no tracking.",
	},
	{
		title:   "The Proof Kitchen",
		tagline: "Bread, mostly. Occasionally something else.",
		sections: []string{
			"A sourdough starter that survives neglect",
			"Hydration, and why the number lies",
			"Cold ferment: a schedule for people with jobs",
		},
		footer: "Recipes are tested at home, in an ordinary oven.",
	},
	{
		title:   "Ledger & Line",
		tagline: "Small tools for small businesses.",
		sections: []string{
			"Invoices that do not need an account",
			"A stock counter for one shelf",
			"Export everything, always",
		},
		footer: "Independent. Nothing here phones home.",
	},
	{
		title:   "Two Rivers Cycling",
		tagline: "Routes, repairs and weekend rides.",
		sections: []string{
			"A loop that avoids every main road",
			"Truing a wheel with the frame as your gauge",
			"Winter gloves: an unscientific comparison",
		},
		footer: "Ride reports posted when the weather allows.",
	},
	{
		title:   "Quiet Hours Audio",
		tagline: "Listening notes and room acoustics.",
		sections: []string{
			"Treating a room you are not allowed to drill",
			"Why the first reflection matters most",
			"A cheap measurement microphone, tested",
		},
		footer: "No affiliate links. Opinions are stubbornly personal.",
	},
	{
		title:   "Marginalia Press",
		tagline: "A very small publisher of very short books.",
		sections: []string{
			"Our next four titles",
			"Submissions: what we actually read",
			"On printing in runs of two hundred",
		},
		footer: "Set in Georgia. Printed on paper.",
	},
	{
		title:   "Northwind Allotments",
		tagline: "Notes from plot 14.",
		sections: []string{
			"Tomatoes that survived a bad August",
			"Composting when you have no space",
			"A watering rota that nobody follows",
		},
		footer: "Updated whenever there is something to report.",
	},
	{
		title:   "Sable & Co Joinery",
		tagline: "Hand-cut furniture, made to order.",
		sections: []string{
			"A bench that fits through a doorway",
			"Choosing between oak and ash",
			"Lead times and how we quote",
		},
		footer: "Workshop visits by arrangement.",
	},
}

// pickDecoy derives stable content from a trusted domain or node identity.
func pickDecoy(seed string) (decoyTemplate, string, time.Time) {
	sum := sha256.Sum256([]byte(seed))
	idx := int(binary.BigEndian.Uint32(sum[0:4])) % len(decoyTemplates)
	if idx < 0 {
		idx += len(decoyTemplates)
	}
	accents := []string{"#2f4858", "#33658a", "#55606e", "#3d5a54", "#6b4d3b", "#4a4e69"}
	accent := accents[int(sum[4])%len(accents)]
	// Keep the built-in profile's date stable across restarts and node tags.
	days := int(binary.BigEndian.Uint32(sum[8:12]) % 1461)
	built := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days)
	return decoyTemplates[idx], accent, built
}

func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// Handler is the site for seed as an http.Handler, for a server that answers
// unauthenticated requests in-process (Hysteria2's masquerade) instead of
// forwarding a connection to a listener.
func Handler(seed string) http.Handler {
	handler, _ := HandlerWithConfig(seed, nil)
	return handler
}

// Start binds a loopback listener and serves the site. The port is chosen by
// the OS and is reachable only through a core's fallback or HTTP masquerade.
func Start(seed string) (*Site, error) {
	return StartWithConfig(seed, nil)
}

func StartWithConfig(seed string, config *Config) (*Site, error) {
	handler, err := HandlerWithConfig(seed, config)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen decoy: %w", err)
	}
	connections := 128
	if config != nil && config.MaxConnections > 0 {
		connections = config.MaxConnections
	}
	ln = netutil.LimitListener(ln, connections)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	d := &Site{
		listener:    ln,
		addr:        ln.Addr().String(),
		connections: connections,
		server: &http.Server{
			Handler:           handler,
			Protocols:         &protocols,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    32 << 10,
			HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 32, MaxReceiveBufferPerConnection: 64 << 10, MaxReceiveBufferPerStream: 64 << 10},
		},
	}
	go func() {
		if err := d.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.WithField("err", err).Warn("decoy site stopped")
		}
	}()
	log.WithFields(log.Fields{
		"addr": d.addr,
	}).Info("decoy site serving unauthenticated connections")
	return d, nil
}

// StartTLSCompanion serves the same handler on a UDP node's TCP address. It
// shares the public request budget and never replaces an existing TCP service.
func (d *Site) StartTLSCompanion(address, certFile, keyFile string) error {
	return d.StartTLSCompanionForDomain(address, certFile, keyFile, "")
}

func (d *Site) StartTLSCompanionForDomain(address, certFile, keyFile, domain string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.companion != nil {
		return fmt.Errorf("cover site is closed or already has a TLS listener")
	}
	loader, err := tlscert.NewForDomain(certFile, keyFile, domain, time.Second)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	ln = netutil.LimitListener(ln, d.connections)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	server := &http.Server{Handler: d.server.Handler, Protocols: &protocols,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10,
		HTTP2:     &http.HTTP2Config{MaxConcurrentStreams: 32, MaxReceiveBufferPerConnection: 64 << 10, MaxReceiveBufferPerStream: 64 << 10},
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: loader.GetCertificate},
	}
	child := &Site{listener: ln, server: server, addr: ln.Addr().String()}
	d.companion = child
	go func() {
		if err := server.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Warn("TCP cover site stopped")
		}
	}()
	return nil
}

// Close stops the site. Safe on a nil Site and safe to repeat.
func (d *Site) Close() error {
	if d == nil {
		return nil
	}
	var err error
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		child := d.companion
		d.mu.Unlock()
		err = errors.Join(d.server.Close(), child.Close())
	})
	return err
}

// Addr is the site's loopback address, "127.0.0.1:port".
func (d *Site) Addr() string { return d.addr }

// URL is the site's address as an http URL, for a reverse-proxy masquerade.
func (d *Site) URL() string { return "http://" + d.addr }

// HostPort splits Addr, for a sing-box fallback's ServerOptions.
func (d *Site) HostPort() (string, uint16) {
	host, portStr, err := net.SplitHostPort(d.addr)
	if err != nil {
		return "127.0.0.1", 0
	}
	var port uint16
	_, _ = fmt.Sscan(portStr, &port)
	return host, port
}

// Seed keeps the site stable for a node: same node, same site, restart after
// restart. format.UserTag-style joining keeps it readable in logs.
func Seed(tag string) string {
	return format.UserTag("decoy", tag)
}
