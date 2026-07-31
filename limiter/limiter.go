package limiter

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/juju/ratelimit"
)

var limitLock sync.RWMutex
var limiter map[string]*Limiter

func Init() {
	limiter = map[string]*Limiter{}
}

type Limiter struct {
	DomainRules   []*regexp.Regexp
	ProtocolRules []string
	SpeedLimit    int
	UserOnlineIP  *sync.Map    // Key: TagUUID, value: {Key: Ip, value: Uid}
	OldUserOnline *sync.Map    // Key: Ip, value: Uid
	UserLimitInfo *sync.Map    // Key: TagUUID value: *UserLimitInfo
	SpeedLimiter  *sync.Map    // key: TagUUID, value: *ratelimit.Bucket
	AliveList     map[int]int  // Key: Uid, value: alive_ip
	aliveMu       sync.RWMutex // guards AliveList (read per-connection, replaced by the node task)

	checks  atomic.Int64 // total CheckLimit calls (for metrics)
	rejects atomic.Int64 // CheckLimit calls that rejected (device/ip limit)
}

// UserLimitInfo holds the limits enforced for one user on one node.
//
// Every field except UID is written by the node's poll / speed-checker
// goroutines while CheckLimit reads them on every single connection, so they
// are atomic: the enclosing sync.Map guards the map, NOT the struct it points
// at. Plain fields here were a data race (confirmed by the race detector:
// UpdateDynamicSpeedLimit writing ExpireTime against CheckLimit reading it).
type UserLimitInfo struct {
	UID               int // immutable after construction
	SpeedLimit        atomic.Int64
	DeviceLimit       atomic.Int64
	DynamicSpeedLimit atomic.Int64
	ExpireTime        atomic.Int64
	OverLimit         atomic.Bool
}

func newUserLimitInfo(u *panel.UserInfo) *UserLimitInfo {
	info := &UserLimitInfo{UID: u.Id}
	info.SpeedLimit.Store(int64(u.SpeedLimit))
	info.DeviceLimit.Store(int64(u.DeviceLimit))
	return info
}

func AddLimiter(tag string, l *conf.LimitConfig, users []panel.UserInfo, aliveList map[int]int) *Limiter {
	info := &Limiter{
		SpeedLimit:    l.SpeedLimit,
		UserOnlineIP:  new(sync.Map),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
		AliveList:     aliveList,
		OldUserOnline: new(sync.Map),
	}
	for i := range users {
		info.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), newUserLimitInfo(&users[i]))
	}
	limitLock.Lock()
	limiter[tag] = info
	limitLock.Unlock()
	return info
}

func GetLimiter(tag string) (info *Limiter, err error) {
	limitLock.RLock()
	info, ok := limiter[tag]
	limitLock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func DeleteLimiter(tag string) {
	limitLock.Lock()
	delete(limiter, tag)
	limitLock.Unlock()
}

// NodeStat is a point-in-time metrics snapshot for one node's limiter.
type NodeStat struct {
	Tag       string
	Users     int
	OnlineIPs int
	Checks    int64
	Rejects   int64
}

// Snapshot returns metrics for every active node limiter. Intended for a
// periodic metrics scrape, so the O(users) counting cost is acceptable.
func Snapshot() []NodeStat {
	limitLock.RLock()
	defer limitLock.RUnlock()
	out := make([]NodeStat, 0, len(limiter))
	for tag, l := range limiter {
		users := 0
		l.UserLimitInfo.Range(func(_, _ any) bool { users++; return true })
		online := 0
		l.UserOnlineIP.Range(func(_, v any) bool {
			v.(*sync.Map).Range(func(_, _ any) bool { online++; return true })
			return true
		})
		out = append(out, NodeStat{
			Tag:       tag,
			Users:     users,
			OnlineIPs: online,
			Checks:    l.checks.Load(),
			Rejects:   l.rejects.Load(),
		})
	}
	return out
}

// UpdateUser applies node *membership* changes: users that joined or left this
// node's group. It does not carry limit changes — see UpdateUserLimits.
func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	for i := range deleted {
		l.UserLimitInfo.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.UserOnlineIP.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.SpeedLimiter.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.aliveMu.Lock()
		delete(l.AliveList, deleted[i].Id)
		l.aliveMu.Unlock()
	}
	for i := range added {
		l.UserLimitInfo.Store(format.UserTag(tag, added[i].Uuid), newUserLimitInfo(&added[i]))
	}
}

// UpdateUserLimits refreshes the speed/device limits of users that are already
// registered, in place. Membership stays with UpdateUser on purpose: that path
// is driven by compareUserList, which also tears the user out of the core's
// inbound (DelUsers/AddUsers) and so drops their live connections. A limit edit
// must never disconnect anybody, and it doesn't have to: the cores never read
// SpeedLimit/DeviceLimit — only the limiter does.
//
// Before this existed, a device_limit change made in the panel never reached the
// limiter at all (compareUserList keyed users on uuid+speed_limit, so a
// device-limit-only change looked like "nothing changed"), which meant raising a
// locked-out user's limit to rescue them did nothing until the node reloaded.
func (l *Limiter) UpdateUserLimits(tag string, users []panel.UserInfo) {
	for i := range users {
		key := format.UserTag(tag, users[i].Uuid)
		v, ok := l.UserLimitInfo.Load(key)
		if !ok {
			continue // not registered yet — UpdateUser adds them
		}
		u := v.(*UserLimitInfo)
		u.DeviceLimit.Store(int64(users[i].DeviceLimit))
		if old := u.SpeedLimit.Swap(int64(users[i].SpeedLimit)); old != int64(users[i].SpeedLimit) {
			// The bucket is cached per user, not per rate, and is never rebuilt on
			// its own — drop it so the next connection builds one at the new rate.
			l.SpeedLimiter.Delete(key)
		}
	}
}

// SetAliveList atomically replaces the per-user alive-IP counts. Called from the
// periodic node task; guarded because CheckLimit reads AliveList on every
// connection (concurrent map access would otherwise crash the process).
func (l *Limiter) SetAliveList(aliveList map[int]int) {
	l.aliveMu.Lock()
	l.AliveList = aliveList
	l.aliveMu.Unlock()
}

func (l *Limiter) UpdateDynamicSpeedLimit(tag, uuid string, limit int, expire time.Time) error {
	key := format.UserTag(tag, uuid)
	v, ok := l.UserLimitInfo.Load(key)
	if !ok {
		return errors.New("not found")
	}
	info := v.(*UserLimitInfo)
	info.DynamicSpeedLimit.Store(int64(limit))
	info.ExpireTime.Store(expire.Unix())
	// Drop the cached bucket: it is keyed by user only, so a stale one would keep
	// serving the old rate and the throttle would silently never take effect.
	l.SpeedLimiter.Delete(key)
	return nil
}

// admitNewIP decides whether a not-yet-registered source IP may be admitted for
// a user, WITHOUT registering anything or otherwise mutating UserOnlineIP. A
// recently-online IP (grace list) is always admitted and consumed; otherwise it
// is admitted only while the user is still under their device limit. Keeping the
// decision side-effect-free lets CheckLimit reject cleanly, so a locked-out user
// leaves no transient online-IP entry for the report to catch — which is what
// used to pin their alive count and deadlock a single device after a restart.
func (l *Limiter) admitNewIP(ip string, uid, deviceLimit, aliveIp int) bool {
	// The grace list is keyed by IP alone, so it must be matched back to this
	// user: admitting on a bare IP hit let a DIFFERENT user in over their device
	// limit whenever the two shared a public address — routine behind CGNAT.
	if v, ok := l.OldUserOnline.Load(ip); ok && v.(int) == uid {
		l.OldUserOnline.Delete(ip)
		return true
	}
	if deviceLimit > 0 && deviceLimit <= aliveIp {
		return false
	}
	return true
}

// AdmitDevice answers whether ip may become another device for this user,
// using the same decision CheckLimit makes — including the fleet-wide alive
// count and the grace list — but WITHOUT registering the address.
//
// The registration is left out on purpose. A core that tracks its own
// connections reports its own addresses, and letting the limiter record them
// too would list every address twice in the online report: the panel would read
// twice the devices and lock out exactly the users this is meant to protect.
//
// An unknown user is admitted here, unlike in CheckLimit. This answers only
// "is this device over the limit"; membership has already been proven by the
// caller (an mdns handshake carries an HMAC token that must match a registered
// user). Rejecting on absence would turn a moment's lag between the limiter's
// user list and the core's into a refused connection for a paying subscriber.
func (l *Limiter) AdmitDevice(taguuid string, ip string) bool {
	if l == nil {
		return true
	}
	ip = strings.TrimPrefix(ip, "::ffff:")
	v, ok := l.UserLimitInfo.Load(taguuid)
	if !ok {
		return true
	}
	u := v.(*UserLimitInfo)
	l.aliveMu.RLock()
	aliveIp := l.AliveList[u.UID]
	l.aliveMu.RUnlock()
	return l.admitNewIP(ip, u.UID, int(u.DeviceLimit.Load()), aliveIp)
}

func (l *Limiter) CheckLimit(taguuid string, ip string, isTcp bool, noSSUDP bool) (Bucket *ratelimit.Bucket, Reject bool) {
	l.checks.Add(1)
	defer func() {
		if Reject {
			l.rejects.Add(1)
		}
	}()
	// check if ipv4 mapped ipv6
	ip = strings.TrimPrefix(ip, "::ffff:")

	// check and gen speed limit Bucket
	nodeLimit := l.SpeedLimit
	userLimit := 0
	deviceLimit := 0
	var uid int
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		u := v.(*UserLimitInfo)
		uid = u.UID
		deviceLimit = int(u.DeviceLimit.Load())
		dynamic := int(u.DynamicSpeedLimit.Load())
		// The dynamic-limit window is over: clear it and fall back to the user's
		// own limit. This used to Delete the whole UserLimitInfo whenever the user
		// had no personal speed limit — which sent their NEXT connection into the
		// unknown-user branch below and rejected it forever: a permanent ban for
		// exactly the common case (speed_limit = 0, i.e. unlimited).
		if exp := u.ExpireTime.Load(); exp != 0 && exp < time.Now().Unix() {
			if u.ExpireTime.CompareAndSwap(exp, 0) { // exactly one goroutine wins
				u.DynamicSpeedLimit.Store(0)
				l.SpeedLimiter.Delete(taguuid) // drop the throttled bucket so the limit actually lifts
			}
			dynamic = 0
		}
		userLimit = determineSpeedLimit(int(u.SpeedLimit.Load()), dynamic)
	} else {
		return nil, true
	}
	if noSSUDP {
		l.aliveMu.RLock()
		aliveIp := l.AliveList[uid]
		l.aliveMu.RUnlock()
		// Decide BEFORE registering the IP so a rejected connection never leaves a
		// throwaway entry in UserOnlineIP. Otherwise the periodic online report can
		// catch that transient entry and keep re-reporting a user who is actually
		// locked out — pinning the panel's alive count and permanently deadlocking a
		// legitimate single device after a restart (the device_limit=1 lockout).
		if v, loaded := l.UserOnlineIP.Load(taguuid); loaded {
			oldipMap := v.(*sync.Map)
			// Already counted for this user → same device, not a new one → allow.
			if _, exists := oldipMap.Load(ip); !exists {
				if !l.admitNewIP(ip, uid, deviceLimit, aliveIp) {
					return nil, true
				}
				oldipMap.Store(ip, uid)
			}
		} else {
			if !l.admitNewIP(ip, uid, deviceLimit, aliveIp) {
				return nil, true
			}
			newipMap := new(sync.Map)
			newipMap.Store(ip, uid)
			// A concurrent call may have created the user's map first; merge into it.
			if actual, ok := l.UserOnlineIP.LoadOrStore(taguuid, newipMap); ok {
				actual.(*sync.Map).Store(ip, uid)
			}
		}
	}

	limit := int64(determineSpeedLimit(nodeLimit, userLimit)) * 1000000 / 8 // Byte/s
	if limit <= 0 {
		return nil, false
	}
	// Reuse the cached bucket; only build one the first time so a hot
	// connection path doesn't allocate a NewBucketWithQuantum on every call.
	if v, ok := l.SpeedLimiter.Load(taguuid); ok {
		return v.(*ratelimit.Bucket), false
	}
	Bucket = ratelimit.NewBucketWithQuantum(time.Second, limit, limit)
	actual, _ := l.SpeedLimiter.LoadOrStore(taguuid, Bucket)
	return actual.(*ratelimit.Bucket), false
}

func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	var onlineUser []panel.OnlineUser
	l.OldUserOnline = new(sync.Map)
	l.UserOnlineIP.Range(func(key, value interface{}) bool {
		taguuid := key.(string)
		ipMap := value.(*sync.Map)
		ipMap.Range(func(key, value interface{}) bool {
			uid := value.(int)
			ip := key.(string)
			l.OldUserOnline.Store(ip, uid)
			onlineUser = append(onlineUser, panel.OnlineUser{UID: uid, IP: ip})
			return true
		})
		l.UserOnlineIP.Delete(taguuid) // Reset online device
		return true
	})

	return &onlineUser, nil
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}
