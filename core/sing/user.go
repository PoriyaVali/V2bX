package sing

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/log"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/core"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
)

func (b *Sing) AddUsers(p *core.AddUsersParams) (added int, err error) {
	b.users.updateLock.Lock()
	defer b.users.updateLock.Unlock()
	in, found := b.box.Inbound().Get(p.Tag)
	if !found {
		return 0, errors.New("the inbound not found")
	}
	for i := range p.Users {
		if p.Users[i].Uuid == "" {
			return 0, fmt.Errorf("user %d has an empty credential", p.Users[i].Id)
		}
		if p.NodeInfo.Type == "tuic" {
			// TUIC mutates its user list before parsing UUIDs. Reject the whole
			// batch first so one malformed panel value cannot poison future
			// successful updates until the inbound is rebuilt.
			if _, err := uuid.FromString(p.Users[i].Uuid); err != nil {
				return 0, fmt.Errorf("TUIC user %d has an invalid UUID", p.Users[i].Id)
			}
		}
	}
	switch p.NodeInfo.Type {
	case "vless":
		us := make([]option.VLESSUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.VLESSUser{
				Name: p.Users[i].Uuid,
				Flow: p.VAllss.Flow,
				UUID: p.Users[i].Uuid,
			}
		}
		err = in.(*vless.Inbound).AddUsers(us)
	case "vmess":
		us := make([]option.VMessUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.VMessUser{
				Name: p.Users[i].Uuid,
				UUID: p.Users[i].Uuid,
			}
		}
		err = in.(*vmess.Inbound).AddUsers(us)
	case "shadowsocks":
		us := make([]option.ShadowsocksUser, len(p.Users))
		for i := range p.Users {
			var password = p.Users[i].Uuid
			var keyLength int
			switch p.Shadowsocks.Cipher {
			case "2022-blake3-aes-128-gcm":
				keyLength = 16
			case "2022-blake3-aes-256-gcm":
				keyLength = 32
			}
			if keyLength > 0 {
				if len(password) < keyLength {
					return 0, fmt.Errorf("Shadowsocks 2022 user %d credential requires at least %d bytes", p.Users[i].Id, keyLength)
				}
				password = base64.StdEncoding.EncodeToString([]byte(password[:keyLength]))
			}
			us[i] = option.ShadowsocksUser{
				Name:     p.Users[i].Uuid,
				Password: password,
			}
		}
		err = in.(*shadowsocks.MultiInbound).AddUsers(us)
	case "trojan":
		us := make([]option.TrojanUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.TrojanUser{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
		}
		err = in.(*trojan.Inbound).AddUsers(us)
	case "tuic":
		us := make([]option.TUICUser, len(p.Users))
		id := make([]int, len(p.Users))
		for i := range p.Users {
			us[i] = option.TUICUser{
				Name:     p.Users[i].Uuid,
				UUID:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
			id[i] = p.Users[i].Id
		}
		err = in.(*tuic.Inbound).AddUsers(us, id)
	case "hysteria":
		us := make([]option.HysteriaUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.HysteriaUser{
				Name:       p.Users[i].Uuid,
				AuthString: p.Users[i].Uuid,
			}
		}
		err = in.(*hysteria.Inbound).AddUsers(us)
	case "hysteria2":
		us := make([]option.Hysteria2User, len(p.Users))
		id := make([]int, len(p.Users))
		for i := range p.Users {
			us[i] = option.Hysteria2User{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
			id[i] = p.Users[i].Id
		}
		err = in.(*hysteria2.Inbound).AddUsers(us, id)
	case "anytls":
		us := make([]option.AnyTLSUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.AnyTLSUser{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
		}
		err = in.(*anytls.Inbound).AddUsers(us)
	}
	if err != nil {
		return 0, err
	}
	// Publish identities only after the inbound has accepted the complete
	// update. Failed validation must not authorise or bill an unapplied user.
	// The node tag keeps the same subscriber's identities independent.
	b.users.mapLock.Lock()
	defer b.users.mapLock.Unlock()
	if b.users.nodeUsers == nil {
		b.users.nodeUsers = make(map[string]map[string]struct{})
	}
	if b.users.nodeUsers[p.Tag] == nil {
		b.users.nodeUsers[p.Tag] = make(map[string]struct{})
	}
	for i := range p.Users {
		b.users.uidMap[format.UserTag(p.Tag, p.Users[i].Uuid)] = p.Users[i].Id
		b.users.nodeUsers[p.Tag][p.Users[i].Uuid] = struct{}{}
	}
	return len(p.Users), err
}

func (b *Sing) GetUserTraffic(tag, uuid string, reset bool) (up int64, down int64) {
	if v, ok := b.hookServer.counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		up = c.GetUpCount(uuid)
		down = c.GetDownCount(uuid)
		if reset {
			c.Reset(uuid)
		}
		return
	}
	return 0, 0
}

func (b *Sing) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	hook := b.hookServer
	b.users.mapLock.Lock()
	defer b.users.mapLock.Unlock()
	trafficSlice := b.retiredTrafficLocked(tag, reset)
	if v, ok := hook.counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		c.Counters.Range(func(key, value interface{}) bool {
			uuid := key.(string)
			uid := b.users.uidMap[format.UserTag(tag, uuid)]
			if uid == 0 {
				c.Delete(uuid)
				return true
			}
			traffic := value.(*counter.TrafficStorage)
			up := traffic.UpCounter.Load()
			down := traffic.DownCounter.Load()
			if up+down > b.nodeReportMinTrafficBytes[tag] {
				if reset {
					// Swap, not Store(0): bytes counted between the Load above and a
					// plain reset were wiped without ever being reported.
					up = traffic.UpCounter.Swap(0)
					down = traffic.DownCounter.Swap(0)
				}
				trafficSlice = append(trafficSlice, panel.UserTraffic{
					UID:      uid,
					Upload:   up,
					Download: down,
				})
			}
			return true
		})
	}
	if len(trafficSlice) == 0 {
		return nil, nil
	}
	// The same UID can have active bytes and one retired accumulator during
	// reload, or change credentials while retaining its panel account.
	byUID := make(map[int]int, len(trafficSlice))
	merged := make([]panel.UserTraffic, 0, len(trafficSlice))
	for _, traffic := range trafficSlice {
		if index, found := byUID[traffic.UID]; found {
			merged[index].Upload += traffic.Upload
			merged[index].Download += traffic.Download
		} else {
			byUID[traffic.UID] = len(merged)
			merged = append(merged, traffic)
		}
	}
	return merged, nil
}

type UserDeleter interface {
	DelUsers(uuid []string) error
}

// removeUsers serialises protocol mutations with AddUsers, then revokes
// membership and detaches the old connection sets atomically. Actual stream
// closes happen after this returns, outside both user locks.
func (b *Sing) removeUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) (*retiredConnections, error) {
	b.users.updateLock.Lock()
	defer b.users.updateLock.Unlock()
	var del UserDeleter
	if i, found := b.box.Inbound().Get(tag); found {
		switch info.Type {
		case "vmess":
			del = i.(*vmess.Inbound)
		case "vless":
			del = i.(*vless.Inbound)
		case "shadowsocks":
			del = i.(*shadowsocks.MultiInbound)
		case "trojan":
			del = i.(*trojan.Inbound)
		case "tuic":
			del = i.(*tuic.Inbound)
		case "hysteria":
			del = i.(*hysteria.Inbound)
		case "hysteria2":
			del = i.(*hysteria2.Inbound)
		case "anytls":
			del = i.(*anytls.Inbound)
		}
	} else {
		return nil, errors.New("the inbound not found")
	}
	uuids := make([]string, len(users))
	for i := range users {
		uuids[i] = users[i].Uuid
	}
	if err := del.DelUsers(uuids); err != nil {
		return nil, err
	}
	// Some inbounds close physical sockets inside DelUsers. Do not hold the
	// global membership lock during those network operations.
	b.users.mapLock.Lock()
	defer b.users.mapLock.Unlock()
	return b.retireUsersLocked(tag, uuids), nil
}

func (b *Sing) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	list, err := b.removeUsers(users, tag, info)
	if err != nil {
		return err
	}
	// Closing an AnyTLS stream may wait for its FIN write. The old generation
	// is already detached, so this cannot block another node's admission or
	// close a connection registered after this user is re-added.
	if n := b.closeRetired(tag, list); n > 0 {
		log.Info("closed ", n, " live connection(s) for ", len(users), " removed user(s) on ", tag)
	}
	return nil
}

// GetDeviceTrafficSlice reports, per user id, the bytes each of that user's
// source addresses moved this cycle - the data device_online_min_traffic needs
// in order to mean "devices whose own traffic passed the threshold" rather than
// "every address of a user whose TOTAL passed it".
//
// An empty map is a valid zero-byte sample; nil denotes an unsupported core.
func (b *Sing) GetDeviceTrafficSlice(tag string, reset bool) (map[int]map[string]int64, error) {
	hook := b.hookServer
	if hook == nil {
		return nil, nil
	}
	b.users.mapLock.RLock()
	defer b.users.mapLock.RUnlock()
	data := hook.GetDeviceTraffic(tag, func(uuid string) int {
		return b.users.uidMap[format.UserTag(tag, uuid)]
	}, reset)
	if data == nil {
		// An empty map means this core supports per-device accounting but saw
		// zero bytes. Nil is reserved for cores without that capability.
		data = make(map[int]map[string]int64)
	}
	return data, nil
}

// OnlineDevices keeps established connections visible in every report cycle.
func (b *Sing) OnlineDevices(tag string) ([]panel.OnlineUser, error) {
	if b.hookServer == nil {
		return nil, nil
	}
	b.users.mapLock.RLock()
	defer b.users.mapLock.RUnlock()
	return b.hookServer.OnlineDevices(tag, func(uuid string) int {
		return b.users.uidMap[format.UserTag(tag, uuid)]
	}), nil
}
