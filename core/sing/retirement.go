package sing

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/format"
)

// Each inbound's listener inherits this context. A routing operation which
// outlives Remove must never be admitted into a replacement with the same tag.
type nodeGeneration struct{ tag string }
type nodeGenerationKey struct{}

func generationContext(ctx context.Context, generation *nodeGeneration) context.Context {
	return context.WithValue(ctx, nodeGenerationKey{}, generation)
}

// connectionLifetime keeps the accounting barrier in the data path. Transport
// Close unblocks I/O, but counters execute AFTER that transport operation
// returns. A closed socket alone is therefore not proof its final bytes have
// been counted. Drained closes only after every admitted operation has returned
// through its counter, and admission remains permanently stopped afterward.
type connectionLifetime struct {
	mu        sync.Mutex
	active    int
	stopping  bool
	closed    bool
	finished  bool
	drained   chan struct{}
	onDrained func()
}

func (c *connectionLifetime) begin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopping {
		return false
	}
	c.active++
	return true
}

func (c *connectionLifetime) stop() {
	c.mu.Lock()
	c.stopping = true
	if c.drained == nil {
		c.drained = make(chan struct{})
	}
	c.mu.Unlock()
}

func (c *connectionLifetime) end() {
	c.mu.Lock()
	c.active--
	c.finishLocked()
}

func (c *connectionLifetime) transportClosed(release func()) {
	c.mu.Lock()
	c.closed = true
	c.onDrained = release
	c.finishLocked()
}

// finishLocked consumes the lock and calls tracking callbacks outside it.
func (c *connectionLifetime) finishLocked() {
	if !c.closed || c.active != 0 || c.finished {
		c.mu.Unlock()
		return
	}
	c.finished = true
	release, done := c.onDrained, c.drained
	c.onDrained = nil
	c.mu.Unlock()
	if release != nil {
		release()
	}
	close(done)
}

func (c *connectionLifetime) wait() {
	c.mu.Lock()
	done := c.drained
	c.mu.Unlock()
	<-done
}

// A retired UID has one compact accumulator, regardless of how many times its
// node/user is rebuilt before the next poll. Only still-retiring storages remain
// in parts; completed generations collapse immediately and are not historical
// ledger entries. A reset poll removes the final accumulator. Nonzero bytes
// necessarily remain until collected by the controller's durable report queue.
type retiredUserTraffic struct {
	upload, download int64
	parts            map[*counter.TrafficStorage]*retiredTrafficPart
}

type retiredTrafficPart struct {
	uid     int
	storage *counter.TrafficStorage
	closed  atomic.Bool
}

type retiredConnections struct {
	closers []io.Closer
	parts   []*retiredTrafficPart
}

// retireUsersLocked is called with the membership write lock. Counter pointer
// capture, UID revocation and old-set detachment form one generation boundary;
// a fresh add cannot inherit the old UID's bytes or be closed by its teardown.
func (b *Sing) retireUsersLocked(tag string, uuids []string) *retiredConnections {
	retired := &retiredConnections{}
	for _, uuid := range uuids {
		key := format.UserTag(tag, uuid)
		uid := b.users.uidMap[key]
		delete(b.users.uidMap, key)
		delete(b.users.nodeUsers[tag], uuid)
		if b.hookServer == nil {
			continue
		}
		if v, found := b.hookServer.counter.Load(tag); found {
			c := v.(*counter.TrafficCounter)
			if storage, found := c.Counters.LoadAndDelete(uuid); found && uid != 0 {
				part := &retiredTrafficPart{uid: uid, storage: storage.(*counter.TrafficStorage)}
				if b.users.retired == nil {
					b.users.retired = make(map[string]map[int]*retiredUserTraffic)
				}
				if b.users.retired[tag] == nil {
					b.users.retired[tag] = make(map[int]*retiredUserTraffic)
				}
				user := b.users.retired[tag][uid]
				if user == nil {
					user = &retiredUserTraffic{parts: make(map[*counter.TrafficStorage]*retiredTrafficPart)}
					b.users.retired[tag][uid] = user
				}
				user.parts[part.storage] = part
				retired.parts = append(retired.parts, part)
			}
		}
		retired.closers = append(retired.closers, b.hookServer.detachUserConns(tag, []string{uuid})...)
	}
	// Device samples describe CURRENT membership. Main billing storage above
	// retains all final bytes; old device entries must not become a fresh
	// same-credential user's totals after re-addition. Scan once per batch:
	// walking every device for every user makes a large node reload quadratic.
	if b.hookServer != nil && len(uuids) > 0 {
		if v, found := b.hookServer.deviceCounter.Load(tag); found {
			removed := make(map[string]struct{}, len(uuids))
			for _, uuid := range uuids {
				removed[uuid] = struct{}{}
			}
			d := v.(*counter.TrafficCounter)
			d.Counters.Range(func(k, _ any) bool {
				oldUUID, _, valid := splitDeviceKey(k.(string))
				if _, revoked := removed[oldUUID]; valid && revoked {
					d.Delete(k.(string))
					b.hookServer.deviceIdle.Delete(format.UserTag(tag, k.(string)))
				}
				return true
			})
		}
	}
	if len(b.users.nodeUsers[tag]) == 0 {
		delete(b.users.nodeUsers, tag)
	}
	return retired
}

func (b *Sing) retireNodeLocked(tag string) *retiredConnections {
	var uuids []string
	for uuid := range b.users.nodeUsers[tag] {
		uuids = append(uuids, uuid)
	}
	delete(b.users.nodes, tag)
	retired := b.retireUsersLocked(tag, uuids)
	if b.hookServer != nil {
		b.hookServer.counter.Delete(tag)
		b.hookServer.deviceCounter.Delete(tag)
	}
	delete(b.nodeReportMinTrafficBytes, tag)
	return retired
}

func (b *Sing) closeRetired(tag string, retired *retiredConnections) int {
	count := closeDetachedConns(retired.closers)
	// tracked Close joins all counted operations; no future operation can pass
	// its lifetime barrier. This is completion proof, not a quiet-cycle guess.
	for _, part := range retired.parts {
		part.closed.Store(true)
	}
	b.users.mapLock.Lock()
	b.compactRetiredLocked(tag)
	b.users.mapLock.Unlock()
	return count
}

func (b *Sing) compactRetiredLocked(tag string) {
	for uid, user := range b.users.retired[tag] {
		for storage, part := range user.parts {
			if !part.closed.Load() {
				continue
			}
			user.upload += storage.UpCounter.Swap(0)
			user.download += storage.DownCounter.Swap(0)
			delete(user.parts, storage)
		}
		if len(user.parts) == 0 && user.upload == 0 && user.download == 0 {
			delete(b.users.retired[tag], uid)
		}
	}
	if len(b.users.retired[tag]) == 0 {
		delete(b.users.retired, tag)
	}
}

func (b *Sing) retiredTrafficLocked(tag string, reset bool) []panel.UserTraffic {
	b.compactRetiredLocked(tag)
	var result []panel.UserTraffic
	for uid, user := range b.users.retired[tag] {
		up, down := user.upload, user.download
		for storage := range user.parts {
			if reset {
				up += storage.UpCounter.Swap(0)
				down += storage.DownCounter.Swap(0)
			} else {
				up += storage.UpCounter.Load()
				down += storage.DownCounter.Load()
			}
		}
		if up != 0 || down != 0 {
			result = append(result, panel.UserTraffic{UID: uid, Upload: up, Download: down})
		}
		if reset {
			user.upload, user.download = 0, 0
			if len(user.parts) == 0 {
				delete(b.users.retired[tag], uid)
			}
		}
	}
	if len(b.users.retired[tag]) == 0 {
		delete(b.users.retired, tag)
	}
	return result
}

// RetireNode lets Selector collect after teardown before deleting its route to
// this core. Standard polls can also read retained bytes while a node is down.
// Returned samples are consumed even on an error, so a retry cannot bill twice.
func (b *Sing) RetireNode(tag string) ([]panel.UserTraffic, error) {
	err := b.DelNode(tag)
	traffic, trafficErr := b.GetUserTrafficSlice(tag, true)
	if err != nil {
		return traffic, err
	}
	return traffic, trafficErr
}
