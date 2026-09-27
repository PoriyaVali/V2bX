package hy2

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Hysteria2node struct {
	Hy2server     server.Server
	Tag           string
	Logger        *zap.Logger
	EventLogger   server.EventLogger
	TrafficLogger server.TrafficLogger
	// Auth is this node's own user set. There used to be one set for the
	// whole core, so a user of any hysteria2 node could log in to every other
	// one in the process - a tier they had not paid for included - and
	// removing them from one node locked them out of all of them.
	Auth *V2bX
	// masq is the node's TCP masquerade server, if it runs one.
	masq *masqTCP
}

func (n *Hysteria2node) close() error {
	var errs []error
	if n.masq != nil {
		if err := n.masq.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if n.Hy2server != nil {
		if err := n.Hy2server.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h *Hysteria2) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	if info.Hysteria2 == nil {
		return fmt.Errorf("hysteria2: node %s has no hysteria2 params", tag)
	}
	var c serverConfig
	if len(config.Hysteria2ConfigPath) != 0 {
		// An error, not Fatal: a bad file for one node used to end the process
		// and every other node it served.
		v := viper.New()
		v.SetConfigFile(config.Hysteria2ConfigPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("read hysteria2 config %s: %w", config.Hysteria2ConfigPath, err)
		}
		if err := v.Unmarshal(&c); err != nil {
			return fmt.Errorf("parse hysteria2 config %s: %w", config.Hysteria2ConfigPath, err)
		}
	}

	h.mu.Lock()
	if h.Hy2nodes[tag] != nil {
		h.mu.Unlock()
		return fmt.Errorf("hysteria2: node %s already exists", tag)
	}
	hook := h.hooks[tag]
	if hook == nil {
		hook = &HookServer{Tag: tag, logger: h.Logger}
		h.hooks[tag] = hook
	}
	h.mu.Unlock()

	n := &Hysteria2node{
		Tag:    tag,
		Logger: h.Logger,
		EventLogger: &serverLogger{
			Tag:    tag,
			logger: h.Logger,
		},
		TrafficLogger: hook,
		Auth:          &V2bX{usersMap: make(map[string]int)},
	}
	hyconfig, err := n.getHyConfig(info, config, &c)
	if err != nil {
		return err
	}
	hyconfig.Authenticator = n.Auth
	s, err := server.NewServer(hyconfig)
	if err != nil {
		_ = hyconfig.Conn.Close()
		if n.masq != nil {
			_ = n.masq.Close()
		}
		return err
	}
	n.Hy2server = s
	hook.reportMin.Store(config.ReportMinTraffic * 1024)
	hook.auth.Store(n.Auth)

	h.mu.Lock()
	h.Hy2nodes[tag] = n
	h.mu.Unlock()
	go func() {
		if err := s.Serve(); err != nil {
			if !strings.Contains(err.Error(), "quic: server closed") {
				h.Logger.Error("Server Error", zap.Error(err))
			}
		}
	}()
	return nil
}

// DelNode stops the node. Its traffic ledger stays, so what was counted since
// the last report is still reported once the node is back.
func (h *Hysteria2) DelNode(tag string) error {
	h.mu.Lock()
	n := h.Hy2nodes[tag]
	delete(h.Hy2nodes, tag)
	h.mu.Unlock()
	if n == nil {
		// Indexing a missing tag used to dereference a nil server and panic.
		return nil
	}
	return n.close()
}
