package hy2

import (
	"errors"
	"sync"

	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"go.uber.org/zap"
)

var _ vCore.Core = (*Hysteria2)(nil)

type Hysteria2 struct {
	// mu guards Hy2nodes and hooks. Nodes are added and removed by one node's
	// poll goroutine while other nodes' goroutines report and sync users; the
	// maps were plain and unguarded, which Go can end with a fatal
	// "concurrent map read and map write".
	mu       sync.RWMutex
	Hy2nodes map[string]*Hysteria2node
	// hooks keeps each node's traffic ledger across a reload of that node.
	// It used to live and die with the node, so every reload threw away the
	// traffic counted since the last report, unbilled.
	hooks  map[string]*HookServer
	Logger *zap.Logger
}

func init() {
	vCore.RegisterCore("hysteria2", New)
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	loglever := "error"
	if c.Hysteria2Config.LogConfig.Level != "" {
		loglever = c.Hysteria2Config.LogConfig.Level
	}
	log, err := initLogger(loglever, "console")
	if err != nil {
		return nil, err
	}
	return &Hysteria2{
		Hy2nodes: make(map[string]*Hysteria2node),
		hooks:    make(map[string]*HookServer),
		Logger:   log,
	}, nil
}

// node returns the running node for tag, or nil.
func (h *Hysteria2) node(tag string) *Hysteria2node {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.Hy2nodes[tag]
}

func (h *Hysteria2) Protocols() []string {
	return []string{
		"hysteria2",
	}
}

func (h *Hysteria2) Start() error {
	return nil
}

// Close stops every node. One that fails to close no longer keeps the rest
// running.
func (h *Hysteria2) Close() error {
	h.mu.Lock()
	nodes := h.Hy2nodes
	h.Hy2nodes = make(map[string]*Hysteria2node)
	h.mu.Unlock()
	var errs []error
	for _, n := range nodes {
		if err := n.close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h *Hysteria2) Type() string {
	return "hysteria2"
}
