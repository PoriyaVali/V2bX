package core

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	log "github.com/sirupsen/logrus"
)

type Selector struct {
	cores map[string]Core
	// order lists the cores' keys as the config lists them, so every walk over
	// the cores - and above all the choice of core for a node - is the same
	// on every run.
	order []string
	nodes sync.Map
}

func NewSelector(c []conf.CoreConfig) (Core, error) {
	cs := make(map[string]Core, len(c))
	order := make([]string, 0, len(c))
	for _, t := range c {
		key := t.Type
		if t.Name != "" {
			key = t.Name
		}
		if _, dup := cs[key]; dup {
			return nil, fmt.Errorf("duplicate core name %q", key)
		}
		f, ok := cores[strings.ToLower(t.Type)]
		if !ok {
			return nil, errors.New("unknown core type: " + t.Type)
		}
		core1, err := f(&t)
		if err != nil {
			return nil, err
		}
		order = append(order, key)
		cs[key] = core1
	}
	return &Selector{
		cores: cs,
		order: order,
	}, nil
}

func (s *Selector) Start() error {
	for _, name := range s.order {
		err := s.cores[name].Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Selector) Close() error {
	var errs []error
	for _, name := range s.order {
		if err := s.cores[name].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isSupported(protocol string, protocols []string) bool {
	for i := range protocols {
		if protocol == protocols[i] {
			return true
		}
	}
	return false
}

func (s *Selector) AddNode(tag string, info *panel.NodeInfo, option *conf.Options) error {
	var core Core
	if len(option.CoreName) > 0 {
		// use name to select core
		if c, ok := s.cores[option.CoreName]; ok {
			core = c
		}
	} else {
		// use type to select core: the first one in config order that fits.
		// This ranged over a map and kept the LAST match, so when two cores
		// could serve the protocol the node landed on either at random.
		for _, name := range s.order {
			c := s.cores[name]
			if len(option.Core) == 0 {
				if !isSupported(info.Type, c.Protocols()) {
					continue
				}
			} else if option.Core != c.Type() {
				continue
			}
			core = c
			break
		}
	}
	if core == nil {
		return errors.New("the node type is not support")
	}
	if len(option.Core) == 0 {
		// First placement of this node: parse its options for the core it
		// landed on.
		raw := option.RawOptions
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		option.Core = core.Type()
		err := option.UnmarshalJSON(raw)
		if err != nil {
			return fmt.Errorf("unmarshal option error: %s", err)
		}
		option.RawOptions = nil
		// Pin the choice. UnmarshalJSON clears Core for a core that has no
		// options of its own (mdns, trusttunnel); with RawOptions already
		// consumed, the next AddNode - every reload of the node - then tried
		// to parse nothing, failed, and the node never came back.
		option.Core = core.Type()
	}
	err := core.AddNode(tag, info, option)
	if err != nil {
		return err
	}
	s.nodes.Store(tag, core)
	warnRulesNotEnforced(tag, core.Type(), info)
	return nil
}

// warnRulesNotEnforced says so when a node carries panel rules its core does
// not apply. The blocking rules are enforced where connections are routed
// through the limiter - the xray and sing cores - and the per-node outbounds
// by xray alone (sing warns for those itself). Without this an operator had
// no way to learn that a rule set in the panel did nothing on this node.
func warnRulesNotEnforced(tag, coreType string, info *panel.NodeInfo) {
	if coreType == "xray" || coreType == "sing" {
		return
	}
	r := info.Rules
	blocking := len(r.Regexp) + len(r.Domain) + len(r.Protocol) + len(r.IP) + len(r.Port)
	if blocking == 0 && len(info.RouteRules) == 0 {
		return
	}
	log.WithFields(log.Fields{
		"tag":         tag,
		"core":        coreType,
		"block_rules": blocking,
		"route_rules": len(info.RouteRules),
	}).Warn("The panel's route rules are not applied by this core; they take effect on xray (all of them) and sing (blocking only)")
}

func (s *Selector) DelNode(tag string) error {
	if t, e := s.nodes.Load(tag); e {
		err := t.(Core).DelNode(tag)
		if err != nil {
			return err
		}
		s.nodes.Delete(tag)
		return nil
	}
	return errors.New("the node is not have")
}

func (s *Selector) AddUsers(p *AddUsersParams) (added int, err error) {
	t, e := s.nodes.Load(p.Tag)
	if !e {
		return 0, errors.New("the node is not have")
	}
	return t.(Core).AddUsers(p)
}

func (s *Selector) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, errors.New("the node is not have")
	}
	return t.(Core).GetUserTrafficSlice(tag, reset)
}

// GetDeviceTrafficSlice forwards to whichever core owns the tag, for the cores
// that can answer it.
//
// This forwarding is load-bearing rather than tidy: a node running more than one
// core - "Core Selector(sing mdns)" in the startup log, which is every node here
// - hands the controller a *Selector, not the core itself. The caller reaches
// this through a type assertion, so without this method the assertion simply
// fails and per-device traffic goes unused: no error, no log, the online report
// quietly keeps its old per-user behaviour. Cores that do not implement it (xray,
// hysteria2, mdns) return nil, and the caller falls back the same way.
func (s *Selector) GetDeviceTrafficSlice(tag string, reset bool) (map[int]map[string]int64, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, errors.New("the node is not have")
	}
	dp, ok := t.(interface {
		GetDeviceTrafficSlice(tag string, reset bool) (map[int]map[string]int64, error)
	})
	if !ok {
		return nil, nil
	}
	return dp.GetDeviceTrafficSlice(tag, reset)
}

// OnlineDevices forwards to whichever core owns the tag, for the cores that
// track their own connections instead of going through the limiter.
//
// Same reason GetDeviceTrafficSlice is forwarded: every node here runs a
// selector, so the controller holds a *Selector and its type assertion would
// fail without a method on this type — silently, leaving mdns users invisible
// to device counting. Cores that do not implement it return nothing.
func (s *Selector) OnlineDevices(tag string) ([]panel.OnlineUser, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, errors.New("the node is not have")
	}
	op, ok := t.(interface {
		OnlineDevices(tag string) ([]panel.OnlineUser, error)
	})
	if !ok {
		return nil, nil
	}
	return op.OnlineDevices(tag)
}

// UpdateUserLimits pushes changed speed limits to a core that enforces them
// itself. Most cores read limits through the limiter on every connection and
// need nothing here.
func (s *Selector) UpdateUserLimits(tag string, users []panel.UserInfo) {
	t, e := s.nodes.Load(tag)
	if !e {
		return
	}
	if up, ok := t.(interface {
		UpdateUserLimits(tag string, users []panel.UserInfo)
	}); ok {
		up.UpdateUserLimits(tag, users)
	}
}

func (s *Selector) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	t, e := s.nodes.Load(tag)
	if !e {
		return errors.New("the node is not have")
	}
	return t.(Core).DelUsers(users, tag, info)
}

func (s *Selector) Protocols() []string {
	protocols := make([]string, 0)
	for _, name := range s.order {
		protocols = append(protocols, s.cores[name].Protocols()...)
	}
	return protocols
}

func (s *Selector) Type() string {
	t := "Selector("
	for i, name := range s.order {
		if i > 0 {
			t += " "
		}
		if len(name) == 0 {
			t += s.cores[name].Type()
		} else {
			t += name
		}
	}
	t += ")"
	return t
}
