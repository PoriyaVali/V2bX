package mdns

import (
	"fmt"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/limiter"
	mdnssrv "masterdnsvpn-go/server"
)

func (m *Mdns) AddNode(tag string, info *panel.NodeInfo, _ *conf.Options) error {
	if info.Mdns == nil {
		return fmt.Errorf("mdns: node %s has no mdns params", tag)
	}

	srv, err := mdnssrv.New(mdnssrv.Options{
		Domains:          info.Mdns.Domain,
		UDPPort:          info.Mdns.ServerPort,
		EncryptionMethod: info.Mdns.EncryptionMethod,
		EncryptionKey:    info.Mdns.EncryptionKey,
		NodeSecret:       info.Mdns.NodeSecret,
		LogLevel:         "error",
	})
	if err != nil {
		return fmt.Errorf("mdns: build server for %s: %w", tag, err)
	}
	// Enforce the device limit at the handshake. The tunnel counts devices but
	// cannot act on the count: a limit belongs to the subscription and is
	// counted across every node the subscriber may be on, which only the limiter
	// knows. Looked up per handshake rather than captured here, because the
	// limiter for this tag is created by the node controller and may not exist
	// yet when the node starts - and a missing limiter admits, since refusing
	// during a startup race would lock out a paying subscriber on the one core
	// that exists to work when nothing else does.
	srv.SetSessionAuthorizer(func(uuid, ip string) bool {
		l, err := limiter.GetLimiter(tag)
		if err != nil {
			return true
		}
		return l.AdmitDevice(format.UserTag(tag, uuid), ip)
	})

	if err := srv.Start(); err != nil {
		return fmt.Errorf("mdns: start server for %s: %w", tag, err)
	}

	m.mu.Lock()
	m.nodes[tag] = &node{server: srv}
	m.mu.Unlock()
	return nil
}

func (m *Mdns) DelNode(tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.nodes[tag]; ok {
		_ = n.server.Close()
		delete(m.nodes, tag)
	}
	return nil
}
