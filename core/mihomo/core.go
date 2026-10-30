// Package mihomo embeds isolated server listeners from PoriyaVali/mihomo.
// It deliberately does not start the client tunnel, controller, or global config.
package mihomo

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
)

type Core struct {
	mu     sync.Mutex
	nodes  map[string]*node
	config conf.MihomoConfig
	closed bool
}

var _ vCore.Core = (*Core)(nil)
var _ vCore.NodeRetirer = (*Core)(nil)

func init() { vCore.RegisterCore("mihomo", New) }
func New(c *conf.CoreConfig) (vCore.Core, error) {
	cfg := *conf.NewMihomoConfig()
	if c != nil && c.MihomoConfig != nil {
		cfg = *c.MihomoConfig
	}
	if cfg.DialTimeout <= 0 || cfg.UDPTimeout <= 0 {
		return nil, errors.New("mihomo timeouts must be positive seconds")
	}
	return &Core{nodes: make(map[string]*node), config: cfg}, nil
}
func (*Core) Type() string { return "mihomo" }
func (*Core) Protocols() []string {
	return []string{"http", "socks5", "mieru", "shadowquic", "sudoku", "snell", "vmess", "vless", "trojan", "tuic", "hysteria2", "anytls", "trusttunnel"}
}
func (*Core) Start() error { return nil }
func (c *Core) get(tag string) (*node, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.nodes[tag]
	if n == nil {
		return nil, fmt.Errorf("mihomo node %q not found", tag)
	}
	return n, nil
}
func (c *Core) AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return netClosed()
	}
	if _, ok := c.nodes[tag]; ok {
		return fmt.Errorf("duplicate mihomo node %q", tag)
	}
	if info == nil || info.Common == nil || options == nil {
		return errors.New("missing mihomo node configuration")
	}
	supported := false
	for _, p := range c.Protocols() {
		if p == info.Type {
			supported = true
		}
	}
	if !supported {
		return fmt.Errorf("mihomo has no managed multi-user server for %q", info.Type)
	}
	// Never silently turn a panel's custom routing or DNS policy into direct routing.
	if len(info.RouteRules) > 0 || len(info.RawDNS.DNSJson) > 0 || len(info.RawDNS.DNSMap) > 0 {
		return errors.New("mihomo server core does not support custom panel DNS or outbound routes")
	}
	l, err := limiter.GetLimiter(tag)
	if err != nil {
		return fmt.Errorf("mihomo requires the node limiter: %w", err)
	}
	n, err := newNode(tag, info, options, c.config, l)
	if err != nil {
		return err
	}
	// Empty user sets keep the port closed, including protocols whose SDK treats
	// an empty authentication map as 'allow all'. First AddUsers binds the port.
	c.nodes[tag] = n
	return nil
}
func netClosed() error { return errors.New("mihomo core is closed") }
func (c *Core) AddUsers(p *vCore.AddUsersParams) (int, error) {
	if p == nil {
		return 0, errors.New("missing users")
	}
	n, e := c.get(p.Tag)
	if e != nil {
		return 0, e
	}
	n.changeMu.Lock()
	defer n.changeMu.Unlock()
	return n.addUsers(p.Users)
}
func (c *Core) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	n, e := c.get(tag)
	if e != nil {
		return e
	}
	n.changeMu.Lock()
	defer n.changeMu.Unlock()
	return n.delUsers(users)
}
func (c *Core) RetireNode(tag string) ([]panel.UserTraffic, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.nodes[tag]
	if n == nil {
		return nil, nil
	}
	n.changeMu.Lock()
	defer n.changeMu.Unlock()
	err := n.close()
	if err != nil {
		return nil, err
	}
	out := n.traffic(true)
	delete(c.nodes, tag)
	return out, nil
}
func (c *Core) DelNode(tag string) error { _, e := c.RetireNode(tag); return e }
func (c *Core) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	var errs []error
	for tag, n := range c.nodes {
		n.changeMu.Lock()
		e := n.close()
		n.changeMu.Unlock()
		if e != nil {
			errs = append(errs, e)
		} else {
			delete(c.nodes, tag)
		}
	}
	return errors.Join(errs...)
}
func (c *Core) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	n, e := c.get(tag)
	if e != nil {
		return nil, e
	}
	return n.traffic(reset), nil
}
func (c *Core) OnlineDevices(tag string) ([]panel.OnlineUser, error) {
	n, e := c.get(tag)
	if e != nil {
		return nil, e
	}
	return n.online(), nil
}
func (c *Core) GetDeviceTrafficSlice(tag string, reset bool) (map[int]map[string]int64, error) {
	n, e := c.get(tag)
	if e != nil {
		return nil, e
	}
	return n.deviceTraffic(reset), nil
}

// Limit-only edits are read by the shared live limiter on established flows.
func (*Core) UpdateUserLimits(string, []panel.UserInfo) {}

type server interface{ io.Closer }
