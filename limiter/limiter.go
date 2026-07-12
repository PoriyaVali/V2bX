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
	UserOnlineIP  *sync.Map      // Key: TagUUID, value: {Key: Ip, value: Uid}
	OldUserOnline *sync.Map      // Key: Ip, value: Uid
	UUIDtoUID     map[string]int // Key: UUID, value: Uid
	UserLimitInfo *sync.Map      // Key: TagUUID value: UserLimitInfo
	SpeedLimiter  *sync.Map      // key: TagUUID, value: *ratelimit.Bucket
	AliveList     map[int]int    // Key: Uid, value: alive_ip
	aliveMu       sync.RWMutex   // guards AliveList (read per-connection, replaced by the node task)

	checks  atomic.Int64 // total CheckLimit calls (for metrics)
	rejects atomic.Int64 // CheckLimit calls that rejected (device/ip limit)
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
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
	uuidmap := make(map[string]int)
	for i := range users {
		uuidmap[users[i].Uuid] = users[i].Id
		userLimit := &UserLimitInfo{}
		userLimit.UID = users[i].Id
		if users[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = users[i].DeviceLimit
		}
		userLimit.OverLimit = false
		info.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), userLimit)
	}
	info.UUIDtoUID = uuidmap
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

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	for i := range deleted {
		l.UserLimitInfo.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.UserOnlineIP.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.SpeedLimiter.Delete(format.UserTag(tag, deleted[i].Uuid))
		delete(l.UUIDtoUID, deleted[i].Uuid)
		l.aliveMu.Lock()
		delete(l.AliveList, deleted[i].Id)
		l.aliveMu.Unlock()
	}
	for i := range added {
		userLimit := &UserLimitInfo{
			UID: added[i].Id,
		}
		if added[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = added[i].SpeedLimit
			userLimit.ExpireTime = 0
		}
		if added[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = added[i].DeviceLimit
		}
		userLimit.OverLimit = false
		l.UserLimitInfo.Store(format.UserTag(tag, added[i].Uuid), userLimit)
		l.UUIDtoUID[added[i].Uuid] = added[i].Id
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
	if v, ok := l.UserLimitInfo.Load(format.UserTag(tag, uuid)); ok {
		info := v.(*UserLimitInfo)
		info.DynamicSpeedLimit = limit
		info.ExpireTime = expire.Unix()
	} else {
		return errors.New("not found")
	}
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
	if v, ok := l.OldUserOnline.Load(ip); ok {
		if v.(int) == uid {
			l.OldUserOnline.Delete(ip)
		}
		return true
	}
	if deviceLimit > 0 && deviceLimit <= aliveIp {
		return false
	}
	return true
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
		deviceLimit = u.DeviceLimit
		uid = u.UID
		if u.ExpireTime < time.Now().Unix() && u.ExpireTime != 0 {
			if u.SpeedLimit != 0 {
				userLimit = u.SpeedLimit
				u.DynamicSpeedLimit = 0
				u.ExpireTime = 0
			} else {
				l.UserLimitInfo.Delete(taguuid)
			}
		} else {
			userLimit = determineSpeedLimit(u.SpeedLimit, u.DynamicSpeedLimit)
		}
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
