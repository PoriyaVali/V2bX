package node

import (
	"strconv"

	"github.com/PoriyaVali/V2bX/api/panel"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	userTraffic, _ := c.server.GetUserTrafficSlice(c.tag, true)

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

	if onlineDevice, err := c.limiter.GetOnlineDevice(); err != nil {
		log.Print(err)
	} else if len(*onlineDevice) > 0 {
		// device_online_min_traffic: prefer the panel value (dynamic), fall
		// back to the node's config.json value when the panel doesn't send it.
		deviceMin := c.Options.DeviceOnlineMinTraffic
		if c.info != nil && c.info.DeviceOnlineMinTraffic > 0 {
			deviceMin = c.info.DeviceOnlineMinTraffic
		}
		var result []panel.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total < deviceMin*1000 {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
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
			log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(*onlineDevice), len(result))
			log.WithField("tag", c.tag).Debugf("Online users: %+v", data)
		}
	}

	userTraffic = nil
	return nil
}

func compareUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int)
	for i, user := range old {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		oldMap[key] = i
	}

	for _, user := range new {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		if _, exists := oldMap[key]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, key)
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
