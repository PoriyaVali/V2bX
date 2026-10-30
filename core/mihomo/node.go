package mihomo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/component/nat"
	C "github.com/metacubex/mihomo/constant"
)

type user struct {
	id                   int
	uuid, name, password string
	traffic              counter.TrafficStorage
	devices              map[string]*counter.TrafficStorage // guarded by node.mu
}
type flow struct {
	control  bool
	onFinish func()
	user     *user
	source   string
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	closers  []io.Closer
	done     chan struct{}
}

func (f *flow) attach(c io.Closer) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		_ = c.Close()
		return false
	}
	f.closers = append(f.closers, c)
	return true
}
func (f *flow) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.cancel()
	closers := f.closers
	f.mu.Unlock()
	for _, c := range closers {
		_ = c.Close()
	}
}

type udpJob struct {
	packet     C.UDPPacket
	metadata   C.Metadata
	generation uint64
}
type node struct {
	queuedBytes atomic.Int64
	changeMu    sync.Mutex // membership and listener replacement
	mu          sync.Mutex // short admission/accounting lock; never held during network IO
	tag         string
	info        *panel.NodeInfo
	options     *conf.Options
	config      conf.MihomoConfig
	limiter     *limiter.Limiter
	ctx         context.Context
	cancel      context.CancelFunc
	closed      bool
	reloading   bool
	generation  uint64
	users       map[string]*user // authenticated name, never a client-provided UID
	records     []*user          // removed identities retained until their counters are drained
	flows       map[*flow]struct{}
	udp         map[udpKey]*udpFlow
	packets     chan udpJob
	workers     sync.WaitGroup
	server      *managedServer
	sockets     *socketFactory
	nat         C.NatTable
	lookup      func(context.Context, string, string) ([]netip.Addr, error)
	// revoked holds the names removed from the running listener and their
	// passwords. A session the protocol keeps open (a Mieru or ShadowQUIC
	// session, an HTTP keep-alive connection) may still carry one.
	revoked map[string]string
}

func newNode(tag string, info *panel.NodeInfo, opt *conf.Options, cfg conf.MihomoConfig, l *limiter.Limiter) (*node, error) {
	if opt.CertConfig != nil && opt.CertConfig.RejectUnknownSni {
		return nil, errors.New("mihomo does not support RejectUnknownSni yet")
	}
	if opt.SendIP != "" && net.ParseIP(opt.SendIP) == nil {
		return nil, errors.New("invalid SendIP")
	}
	if info.Common.ServerPort < 1 || info.Common.ServerPort > 65535 {
		return nil, errors.New("invalid server port")
	}
	// {{user_id}} is a public sequence number. Without the subscriber's UUID in
	// either credential, anyone could log in, and be billed, as anyone else.
	if m := info.Mihomo; m != nil && !strings.Contains(credentialTemplate(m.Username)+credentialTemplate(m.Password), "{{uuid}}") {
		return nil, errors.New("mihomo credentials must include {{uuid}} in the username or password")
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &node{tag: tag, info: info, options: opt, config: cfg, limiter: l, ctx: ctx, cancel: cancel, users: map[string]*user{}, flows: map[*flow]struct{}{}, udp: map[udpKey]*udpFlow{}, packets: make(chan udpJob, 256), nat: nat.New(), lookup: net.DefaultResolver.LookupNetIP}
	// Validate before publishing the node, even when it currently has no users.
	if _, e := n.buildServer(nil); e != nil {
		cancel()
		return nil, e
	}
	n.workers.Add(1)
	go n.udpWorker()
	return n, nil
}

// credentialTemplate is the template an empty panel field stands for.
func credentialTemplate(template string) string {
	if template == "" {
		return "{{uuid}}"
	}
	return template
}
func credential(template string, u panel.UserInfo) string {
	return strings.NewReplacer("{{uuid}}", u.Uuid, "{{user_id}}", strconv.Itoa(u.Id)).Replace(credentialTemplate(template))
}
func (n *node) makeUser(u panel.UserInfo) (*user, error) {
	if u.Id <= 0 || u.Uuid == "" {
		return nil, errors.New("invalid user identity")
	}
	name, password := u.Uuid, u.Uuid
	if n.info.Type == "vmess" || n.info.Type == "vless" || n.info.Type == "tuic" {
		id, e := uuid.FromString(u.Uuid)
		if e != nil {
			return nil, errors.New("protocol requires valid user UUIDs")
		}
		if n.info.Type == "tuic" {
			name = id.String()
		}
	}

	if n.info.Mihomo != nil {
		name = credential(n.info.Mihomo.Username, u)
		password = credential(n.info.Mihomo.Password, u)
	}
	if name == "" || password == "" || strings.Contains(name, "{{") || strings.Contains(password, "{{") {
		return nil, errors.New("invalid credential template")
	}
	if n.info.Type == "socks5" && (len(name) > 255 || len(password) > 255) {
		return nil, errors.New("SOCKS credentials exceed 255 bytes")
	}
	return &user{id: u.Id, uuid: u.Uuid, name: name, password: password, devices: map[string]*counter.TrafficStorage{}}, nil
}
func cloneUsers(in map[string]*user) map[string]*user {
	out := make(map[string]*user, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func (n *node) addUsers(users []panel.UserInfo) (int, error) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return 0, netClosed()
	}
	next := cloneUsers(n.users)
	n.mu.Unlock()
	added := []*user{}
	for _, u := range users {
		v, e := n.makeUser(u)
		if e != nil {
			return 0, e
		}
		if old := next[v.name]; old != nil {
			if old.id == v.id && old.uuid == v.uuid {
				continue
			}
			return 0, errors.New("credentials shared by multiple users cannot be metered independently")
		}
		for _, old := range next {
			if old.id == v.id || old.uuid == v.uuid {
				return 0, errors.New("duplicate panel user identity")
			}
		}
		next[v.name] = v
		added = append(added, v)
	}
	if len(added) == 0 {
		return 0, nil
	}
	if e := n.replaceUsers(next); e != nil {
		return 0, e
	}
	n.mu.Lock()
	n.records = append(n.records, added...)
	n.mu.Unlock()
	return len(added), nil
}
func (n *node) delUsers(users []panel.UserInfo) error {
	n.mu.Lock()
	next := cloneUsers(n.users)
	for _, u := range users {
		for name, v := range next {
			if v.uuid == u.Uuid {
				delete(next, name)
			}
		}
	}
	unchanged := len(next) == len(n.users)
	n.mu.Unlock()
	// A rebuild disconnects every session on the node; removing nobody must not.
	if unchanged {
		return nil
	}
	return n.replaceUsers(next)
}

// maxRevoked bounds the removed credentials a running listener remembers; the
// change that would exceed it replaces the listener instead.
const maxRevoked = 4096

func (n *node) replaceUsers(next map[string]*user) error {
	prepared, e := n.buildServer(next)
	if e != nil {
		return e
	}
	if n.updateUsers(next) {
		_ = prepared.Close()
		return nil
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return netClosed()
	}
	previous := n.users
	n.reloading = true
	n.generation++
	n.mu.Unlock()
	defer func() { n.mu.Lock(); n.reloading = false; n.mu.Unlock() }()
	// The other listener SDKs in this fork fix their authentication table when
	// they start, so their membership changes replace the listener; speed edits
	// never enter this path. Close and await old flows before publishing a
	// replacement identity map.
	flows := n.stopFlows()
	if n.server != nil {
		if e = n.server.Close(); e != nil {
			n.awaitFlows(flows)
			return e
		}
		n.server = nil
	}
	if n.sockets != nil {
		n.sockets.Close()
	}
	n.awaitFlows(flows)
	n.mu.Lock()
	n.users = next
	n.revoked = nil
	n.mu.Unlock()
	if len(next) == 0 {
		return nil
	}
	n.mu.Lock()
	n.reloading = false
	n.mu.Unlock()
	e = prepared.Listen(n)
	if e == nil {
		n.server = prepared
		n.sockets = prepared.sockets
		return nil
	}
	_ = prepared.Close()
	n.mu.Lock()
	n.users = previous
	n.mu.Unlock()
	// Restore old users and bind after a failed replacement. Do not swallow a
	// failed rollback: the controller retries the node on the next poll.
	if len(previous) > 0 {
		old, buildErr := n.buildServer(previous)
		if buildErr == nil {
			buildErr = old.Listen(n)
			if buildErr == nil {
				n.server = old
				n.sockets = old.sockets
			} else {
				_ = old.Close()
			}
		}
		if buildErr != nil {
			return errors.Join(fmt.Errorf("mihomo listener replacement: %w", e), fmt.Errorf("rollback: %w", buildErr))
		}
	}
	return fmt.Errorf("mihomo listener replacement: %w", e)
}

// updateUsers changes the users of the running listener in place and closes
// only the flows of the users it removes; everyone else stays connected. It
// reports false when the listener has to be replaced instead: the protocol
// cannot change its users, the node gains its first or loses its last user, or
// a removed name returns with another password while a session may still carry
// the old one.
func (n *node) updateUsers(next map[string]*user) bool {
	if n.server == nil || n.server.update == nil || len(next) == 0 {
		return false
	}
	n.mu.Lock()
	revoked := make(map[string]string, len(n.revoked))
	for name, password := range n.revoked {
		revoked[name] = password
	}
	for name, u := range n.users {
		if v := next[name]; v == nil {
			revoked[name] = u.password
		} else if v != u && v.password != u.password {
			n.mu.Unlock()
			return false
		}
	}
	for name, u := range next {
		if password, ok := revoked[name]; ok {
			if password != u.password {
				n.mu.Unlock()
				return false
			}
			delete(revoked, name)
		}
	}
	n.mu.Unlock()
	if len(revoked) > maxRevoked {
		return false
	}
	// Publish the users to the listener first. Admission then refuses removed
	// users from the moment n.users changes, and every flow admitted before
	// that is in n.flows to be closed.
	if n.server.update(next) != nil {
		return false
	}
	n.mu.Lock()
	n.users = next
	n.revoked = revoked
	var removed []*flow
	for f := range n.flows {
		if next[f.user.name] != f.user {
			removed = append(removed, f)
		}
	}
	n.mu.Unlock()
	// Do not wait for them: unlike a replacement, nothing here closes the
	// client transport a flow may be blocked writing to. Their counters stay in
	// n.records until the flows finish and are drained.
	for _, f := range removed {
		f.close()
	}
	return true
}

// stopFlows closes every flow and returns them for awaitFlows. Close the node's
// sockets in between: a flow may be blocked writing to a client that stopped
// reading (a UDP reply over its stream, a multiplexed stream), and only closing
// the client's transport ends that write.
func (n *node) stopFlows() []*flow {
	n.mu.Lock()
	flows := make([]*flow, 0, len(n.flows))
	for f := range n.flows {
		flows = append(flows, f)
	}
	n.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
	return flows
}
func (n *node) awaitFlows(flows []*flow) {
	for _, f := range flows {
		<-f.done
	}
}
func (n *node) close() error {
	n.mu.Lock()
	n.closed = true
	n.cancel()
	n.mu.Unlock()
	flows := n.stopFlows()
	var err error
	if n.server != nil {
		err = n.server.Close()
		n.server = nil
	}
	if n.sockets != nil {
		n.sockets.Close()
	}
	n.awaitFlows(flows)
	n.workers.Wait()
	return err
}
func (n *node) NatTable() C.NatTable { return n.nat }
func atomicValue(v *atomic.Int64, reset bool) int64 {
	if reset {
		return v.Swap(0)
	}
	return v.Load()
}
func (n *node) traffic(reset bool) []panel.UserTraffic {
	n.mu.Lock()
	defer n.mu.Unlock()
	byID := map[int]*panel.UserTraffic{}
	for _, u := range n.records {
		up, down := atomicValue(&u.traffic.UpCounter, reset), atomicValue(&u.traffic.DownCounter, reset)
		if up == 0 && down == 0 {
			continue
		}
		v := byID[u.id]
		if v == nil {
			v = &panel.UserTraffic{UID: u.id}
			byID[u.id] = v
		}
		v.Upload += up
		v.Download += down
	}
	out := make([]panel.UserTraffic, 0, len(byID))
	for _, v := range byID {
		out = append(out, *v)
	}
	if reset {
		n.pruneRecordsLocked()
	}
	return out
}
func (n *node) deviceTraffic(reset bool) map[int]map[string]int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[int]map[string]int64{}
	for _, u := range n.records {
		for ip, s := range u.devices {
			b := atomicValue(&s.UpCounter, reset) + atomicValue(&s.DownCounter, reset)
			if b == 0 {
				continue
			}
			if out[u.id] == nil {
				out[u.id] = map[string]int64{}
			}
			out[u.id][ip] += b
		}
	}
	if reset {
		n.pruneRecordsLocked()
	}
	return out
}
func (n *node) online() []panel.OnlineUser {
	n.mu.Lock()
	defer n.mu.Unlock()
	byID := map[int]map[string]bool{}
	for f := range n.flows {
		if byID[f.user.id] == nil {
			byID[f.user.id] = map[string]bool{}
		}
		byID[f.user.id][f.source] = true
	}
	var out []panel.OnlineUser
	for id, ips := range byID {
		for ip := range ips {
			out = append(out, panel.OnlineUser{UID: id, IP: ip})
		}
	}
	return out
}

func (n *node) pruneRecordsLocked() {
	live := map[*user]bool{}
	for _, u := range n.users {
		live[u] = true
	}
	for f := range n.flows {
		live[f.user] = true
	}
	kept := n.records[:0]
	for _, u := range n.records {
		pending := u.traffic.UpCounter.Load() != 0 || u.traffic.DownCounter.Load() != 0
		for _, s := range u.devices {
			pending = pending || s.UpCounter.Load() != 0 || s.DownCounter.Load() != 0
		}
		if live[u] || pending {
			kept = append(kept, u)
		}
	}
	for i := len(kept); i < len(n.records); i++ {
		n.records[i] = nil
	}
	n.records = kept
}
