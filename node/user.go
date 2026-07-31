package node

import (
	"github.com/PoriyaVali/V2bX/api/panel"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	userTraffic, _ := c.server.GetUserTrafficSlice(c.tag, true)

	// Feed the dynamic speed-limit accumulator with this cycle's raw per-user
	// traffic (keyed by UID). SpeedChecker consumes and resets it on its own
	// interval; the map is shared across goroutines, so guard it.
	if c.LimitConfig.EnableDynamicSpeedLimit && len(userTraffic) > 0 {
		c.trafficMu.Lock()
		if c.traffic == nil {
			c.traffic = make(map[int]int64)
		}
		for i := range userTraffic {
			c.traffic[userTraffic[i].UID] += userTraffic[i].Upload + userTraffic[i].Download
		}
		c.trafficMu.Unlock()
	}

	// node_report_min_traffic (panel): only report users whose accumulated
	// traffic passes the threshold; the rest is carried over. Device counting
	// below still uses the raw per-cycle userTraffic, so keep it separate.
	toReport := userTraffic
	if c.info != nil && c.info.NodeReportMinTraffic > 0 {
		toReport = c.applyReportMinTraffic(userTraffic)
	}
	if len(toReport) > 0 {
		err = c.apiClient.ReportUserTraffic(toReport)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report user traffic failed")
		} else {
			log.WithField("tag", c.tag).Infof("Report %d users traffic", len(toReport))
			log.WithField("tag", c.tag).Debugf("User traffic: %+v", toReport)
		}
	}

	// The limiter is the usual source of online addresses: every core routes its
	// connections through CheckLimit, which records them. One does not — mdns
	// paces itself inside the tunnel and never calls the limiter — so its users
	// appeared nowhere in this report and no device limit could be enforced on
	// them, while every other protocol in the fleet enforced one. Cores that can
	// answer for themselves are asked and their addresses merged in; cores that
	// cannot are unaffected, since the assertion simply fails.
	var onlineDevice []panel.OnlineUser
	if fromLimiter, err := c.limiter.GetOnlineDevice(); err != nil {
		log.Print(err)
	} else if fromLimiter != nil {
		onlineDevice = *fromLimiter
	}
	if op, ok := c.server.(interface {
		OnlineDevices(tag string) ([]panel.OnlineUser, error)
	}); ok {
		if fromCore, err := op.OnlineDevices(c.tag); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).
				Info("Read online devices from core failed")
		} else if len(fromCore) > 0 {
			onlineDevice = append(onlineDevice, fromCore...)
		}
	}
	if len(onlineDevice) > 0 {
		// device_online_min_traffic: prefer the panel value (dynamic), fall
		// back to the node's config.json value when the panel doesn't send it.
		deviceMin := c.Options.DeviceOnlineMinTraffic
		if c.info != nil && c.info.DeviceOnlineMinTraffic > 0 {
			deviceMin = c.info.DeviceOnlineMinTraffic
		}
		result := onlineDevice
		if deviceMin > 0 {
			// Per-DEVICE first, which is what the panel's own description of this
			// setting promises. Falling back to the per-user gate below only when
			// the core cannot supply per-address traffic.
			//
			// The per-user gate is what made a rotating carrier address look like a
			// crowd: pass the threshold once and EVERY address that user was seen
			// from got reported, so one phone behind a NAT pool that hands out a
			// different egress IP per connection was counted as a dozen devices and
			// the customer was locked out of their own account. Judging each address
			// on its own traffic drops the transient ones that carried a few
			// kilobytes and keeps the one or two doing real work.
			if dp, ok := c.server.(interface {
				GetDeviceTrafficSlice(tag string, reset bool) (map[int]map[string]int64, error)
			}); ok {
				if perDevice, err := dp.GetDeviceTrafficSlice(c.tag, true); err == nil && len(perDevice) > 0 {
					var kept []panel.OnlineUser
					for _, online := range onlineDevice {
						if perDevice[online.UID][online.IP] >= deviceMin*1000 {
							kept = append(kept, online)
						}
					}
					result = kept
					deviceMin = 0 // handled; skip the per-user fallback
				}
			}
		}
		if deviceMin > 0 {
			// Report a user's devices only when we hold a traffic sample for them
			// that reaches the threshold. This used to be phrased as a deny-set
			// ("skip users whose traffic is below it"), which inverted the gate at
			// the zero-byte edge: a user with no sample at all — the core omits
			// users with 0 bytes from the slice — was never added to the deny-set
			// and so WAS reported, while a genuinely active user just under the
			// threshold was not. A dead connection consumed a device slot; a live,
			// lightly-used device did not.
			countUID := make(map[int]struct{}, len(userTraffic))
			for _, traffic := range userTraffic {
				if traffic.Upload+traffic.Download >= deviceMin*1000 {
					countUID[traffic.UID] = struct{}{}
				}
			}
			result = nil
			for _, online := range onlineDevice {
				if _, ok := countUID[online.UID]; ok {
					result = append(result, online)
				}
			}
		}
		data := make(map[int][]string)
		for _, onlineuser := range result {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
		}
		if err = c.apiClient.ReportNodeOnlineUsers(&data); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report online users failed")
		} else {
			log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(onlineDevice), len(result))
			log.WithField("tag", c.tag).Debugf("Online users: %+v", data)
		}
	}

	userTraffic = nil
	return nil
}

// compareUserList reports pure *membership* changes: who joined this node's
// group and who left. It keys on the UUID alone.
//
// It deliberately ignores the users' limits. The added/deleted sets it returns
// drive DelUsers/AddUsers on the core, which tears the user out of the inbound
// and drops their live connections — so folding a limit change in here would
// disconnect a user every time an admin adjusted their plan. Limits are carried
// separately by limiter.UpdateUserLimits, which updates them in place; no core
// involvement is needed because the cores never read them.
func compareUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int, len(old))
	for i, user := range old {
		oldMap[user.Uuid] = i
	}

	for _, user := range new {
		if _, exists := oldMap[user.Uuid]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, user.Uuid)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added
}

// applyReportMinTraffic accumulates each user's per-cycle traffic and only
// returns (reports) users whose accumulated total reached NodeReportMinTraffic
// (kilobytes → ×1000 bytes). Sub-threshold users stay in the accumulator so no
// traffic is lost — it is reported once the total crosses the threshold.
func (c *Controller) applyReportMinTraffic(in []panel.UserTraffic) []panel.UserTraffic {
	threshold := c.info.NodeReportMinTraffic * 1000
	if c.reportAccum == nil {
		c.reportAccum = make(map[int][2]int64)
	}
	for _, t := range in {
		a := c.reportAccum[t.UID]
		a[0] += t.Upload
		a[1] += t.Download
		c.reportAccum[t.UID] = a
	}
	out := make([]panel.UserTraffic, 0, len(c.reportAccum))
	for uid, a := range c.reportAccum {
		if a[0]+a[1] >= threshold {
			out = append(out, panel.UserTraffic{UID: uid, Upload: a[0], Download: a[1]})
			delete(c.reportAccum, uid)
		}
	}
	return out
}
