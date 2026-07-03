package mdns

import (
	"fmt"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
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
