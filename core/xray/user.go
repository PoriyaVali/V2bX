package xray

import (
	"context"
	"fmt"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/counter"
	"github.com/PoriyaVali/V2bX/common/format"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/core/xray/app/dispatcher"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
)

func (c *Xray) GetUserManager(tag string) (proxy.UserManager, error) {
	handler, err := c.ihm.GetHandler(context.Background(), tag)
	if err != nil {
		return nil, fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}
	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.UserManager", tag)
	}
	return userManager, nil
}

func (c *Xray) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	userManager, err := c.GetUserManager(tag)
	if err != nil {
		return fmt.Errorf("get user manager error: %s", err)
	}
	var user string
	c.users.mapLock.Lock()
	defer c.users.mapLock.Unlock()
	for i := range users {
		user = format.UserTag(tag, users[i].Uuid)
		err = userManager.RemoveUser(context.Background(), user)
		if err != nil {
			return err
		}
		uid := c.users.uidMap[user]
		delete(c.users.uidMap, user)
		if v, ok := c.dispatcher.Counter.Load(tag); ok {
			// What the user ran up since the last report is still theirs to
			// be billed. The counter was deleted with them, so up to a whole
			// report interval of traffic was never reported. It is kept for
			// the next report, with the last bytes of the connections closed
			// below, which count into the same counter.
			tc := v.(*counter.TrafficCounter)
			if s, ok := tc.Counters.LoadAndDelete(user); ok {
				c.users.departedOf(tag).Keep(uid, s.(*counter.TrafficStorage))
			}
		}
		if v, ok := c.dispatcher.LinkManagers.Load(user); ok {
			lm := v.(*dispatcher.LinkManager)
			lm.CloseAll()
			c.dispatcher.LinkManagers.Delete(user)
		}
	}
	return nil
}

func (x *Xray) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	trafficSlice := make([]panel.UserTraffic, 0)
	x.users.mapLock.RLock()
	defer x.users.mapLock.RUnlock()
	if v, ok := x.dispatcher.Counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		c.Counters.Range(func(key, value interface{}) bool {
			email := key.(string)
			traffic := value.(*counter.TrafficStorage)
			up := traffic.UpCounter.Load()
			down := traffic.DownCounter.Load()
			if up+down > x.nodeReportMinTrafficBytes[tag] {
				if reset {
					// Swap, not Store(0): bytes counted between the Load above and a
					// plain reset were wiped without ever being reported.
					up = traffic.UpCounter.Swap(0)
					down = traffic.DownCounter.Swap(0)
				}
				if x.users.uidMap[email] == 0 {
					c.Delete(email)
					return true
				}
				trafficSlice = append(trafficSlice, panel.UserTraffic{
					UID:      x.users.uidMap[email],
					Upload:   up,
					Download: down,
				})
			}
			return true
		})
	}
	// Removed users, whatever the node's reporting threshold: they will not
	// add to what they ran up. One who was added back is reported once.
	for _, d := range x.users.departedOf(tag).Take(reset) {
		merged := false
		for i := range trafficSlice {
			if trafficSlice[i].UID == d.UID {
				trafficSlice[i].Upload += d.Upload
				trafficSlice[i].Download += d.Download
				merged = true
				break
			}
		}
		if !merged {
			trafficSlice = append(trafficSlice, panel.UserTraffic{UID: d.UID, Upload: d.Upload, Download: d.Download})
		}
	}
	if len(trafficSlice) == 0 {
		return nil, nil
	}
	return trafficSlice, nil
}

func (c *Xray) AddUsers(p *vCore.AddUsersParams) (added int, err error) {
	c.users.mapLock.Lock()
	defer c.users.mapLock.Unlock()
	var users []*protocol.User
	switch p.NodeInfo.Type {
	case "vmess":
		users = buildVmessUsers(p.Tag, p.Users)
	case "vless":
		users = buildVlessUsers(p.Tag, p.Users, p.VAllss.Flow)
	case "trojan":
		users = buildTrojanUsers(p.Tag, p.Users)
	case "shadowsocks":
		users, err = buildSSUsers(p.Tag,
			p.Users,
			p.Shadowsocks.Cipher,
			p.Shadowsocks.ServerKey)
	default:
		return 0, fmt.Errorf("unsupported node type: %s", p.NodeInfo.Type)
	}
	if err != nil {
		return 0, err
	}
	// Validate the whole batch before installing any user. A malformed panel
	// credential must not leave an earlier user half-installed on the node.
	memoryUsers := make([]*protocol.MemoryUser, len(users))
	for i, u := range users {
		memoryUsers[i], err = u.ToMemoryUser()
		if err != nil {
			return 0, err
		}
	}
	man, err := c.GetUserManager(p.Tag)
	if err != nil {
		return 0, fmt.Errorf("get user manager error: %s", err)
	}
	for i, u := range memoryUsers {
		err = man.AddUser(context.Background(), u)
		if err != nil {
			return added, err
		}
		c.users.uidMap[u.Email] = p.Users[i].Id
		added++
	}
	return added, nil
}
