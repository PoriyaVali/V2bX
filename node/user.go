package node

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/PoriyaVali/V2bX/api/panel"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	// One consistent view of the node: the node-info goroutine may be replacing
	// these while this runs.
	tag, info, lim := c.state()
	userTraffic, trafficErr := c.server.GetUserTrafficSlice(tag, true)
	if trafficErr != nil {
		log.WithFields(log.Fields{"tag": tag, "err": trafficErr}).Warn("Read user traffic failed")
		// The batches earlier cycles could not send do not need the core. Send
		// them anyway: a node that stays down (a reload that failed after
		// DelNode) held its users' billed traffic in memory until it came back,
		// and lost it if the process restarted first.
		c.flushTrafficReports()
		return nil
	}

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
	var reportMin int64
	if info != nil {
		reportMin = info.NodeReportMinTraffic
	}
	if reportMin > 0 || len(c.reportAccum) > 0 {
		// A zero threshold flushes what earlier cycles accumulated below it.
		toReport = c.applyReportMinTraffic(userTraffic, reportMin)
	}
	if len(toReport) > 0 {
		c.queueTrafficReport(toReport)
	}
	c.flushTrafficReports()
	if lim == nil {
		return nil
	}

	// Merge addresses seen at admission with the core's active connections.
	// Established connections must remain visible without a fresh handshake.
	var onlineDevice []panel.OnlineUser
	if fromLimiter, err := lim.GetOnlineDevice(); err != nil {
		log.Print(err)
	} else if fromLimiter != nil {
		onlineDevice = *fromLimiter
	}
	if op, ok := c.server.(interface {
		OnlineDevices(tag string) ([]panel.OnlineUser, error)
	}); ok {
		if fromCore, err := op.OnlineDevices(tag); err != nil {
			log.WithFields(log.Fields{"tag": tag, "err": err}).
				Info("Read online devices from core failed")
		} else if len(fromCore) > 0 {
			onlineDevice = append(onlineDevice, fromCore...)
		}
	}
	// Drain every cycle, including when filtering is disabled or no fresh
	// handshake was seen. Otherwise per-IP counters keep growing indefinitely.
	var perDevice map[int]map[string]int64
	if dp, ok := c.server.(interface {
		GetDeviceTrafficSlice(tag string, reset bool) (map[int]map[string]int64, error)
	}); ok {
		raw, err := dp.GetDeviceTrafficSlice(tag, true)
		if err != nil {
			log.WithFields(log.Fields{"tag": tag, "err": err}).Warn("Read device traffic failed")
		} else if raw != nil {
			perDevice = make(map[int]map[string]int64, len(raw))
			for uid, ips := range raw {
				perDevice[uid] = make(map[string]int64, len(ips))
				for ip, n := range ips {
					ip = strings.TrimPrefix(ip, "::ffff:")
					perDevice[uid][ip] += n
					if n > 0 {
						onlineDevice = append(onlineDevice, panel.OnlineUser{UID: uid, IP: ip})
					}
				}
			}
		}
	}
	// The limiter, active connections and byte samples can describe the same
	// address. Send each user/address pair once.
	seen := make(map[panel.OnlineUser]struct{}, len(onlineDevice))
	unique := onlineDevice[:0]
	for _, online := range onlineDevice {
		online.IP = strings.TrimPrefix(online.IP, "::ffff:")
		if _, exists := seen[online]; !exists {
			seen[online] = struct{}{}
			unique = append(unique, online)
		}
	}
	onlineDevice = unique
	lim.SetOnlineDeviceGrace(onlineDevice)
	if len(onlineDevice) > 0 {
		deviceMin := c.Options.DeviceOnlineMinTraffic
		if info != nil && info.DeviceOnlineMinTraffic > 0 {
			deviceMin = info.DeviceOnlineMinTraffic
		}
		result := onlineDevice
		if deviceMin > 0 && perDevice != nil {
			var kept []panel.OnlineUser
			for _, online := range onlineDevice {
				if perDevice[online.UID][online.IP] >= deviceMin*1000 {
					kept = append(kept, online)
				}
			}
			result = kept
			deviceMin = 0
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
				"tag": tag,
				"err": err,
			}).Info("Report online users failed")
		} else {
			log.WithField("tag", tag).Infof("Total %d online users, %d Reported", len(onlineDevice), len(result))
			log.WithField("tag", tag).Debugf("Online users: %+v", data)
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
func (c *Controller) applyReportMinTraffic(in []panel.UserTraffic, minKB int64) []panel.UserTraffic {
	threshold := minKB * 1000
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

// maxPendingReports bounds how many unsent traffic batches a node holds while
// the panel is unreachable: at a 41 s push interval, about four hours.
const maxPendingReports = 360

// pendingReport is one traffic batch and the id it is sent under. The id stays
// the same across every attempt, which is what lets the panel count it once.
type pendingReport struct {
	id      string
	traffic []panel.UserTraffic
}

func newReportID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// queueTrafficReport adds this cycle's batch behind any that have not gone out.
//
// The core's counters were already reset when the batch was read, so a batch
// that failed to send used to be simply gone - traffic nobody was billed for.
func (c *Controller) queueTrafficReport(traffic []panel.UserTraffic) {
	c.pendingReports = append(c.pendingReports, pendingReport{id: newReportID(), traffic: traffic})
	if over := len(c.pendingReports) - maxPendingReports; over > 0 {
		var lost int64
		for _, r := range c.pendingReports[:over] {
			for _, t := range r.traffic {
				lost += t.Upload + t.Download
			}
		}
		tag, _, _ := c.state()
		log.WithField("tag", tag).Errorf(
			"Panel unreachable for too long: dropping %d unsent traffic report(s), %d bytes", over, lost)
		c.pendingReports = append([]pendingReport(nil), c.pendingReports[over:]...)
	}
}

// flushTrafficReports sends the queued batches oldest first and stops at the
// first failure, keeping the rest for the next cycle. Only the report task
// touches the queue, so it needs no lock.
func (c *Controller) flushTrafficReports() {
	tag, _, _ := c.state()
	for len(c.pendingReports) > 0 {
		r := c.pendingReports[0]
		if err := c.apiClient.ReportUserTrafficWithID(r.id, r.traffic); err != nil {
			log.WithFields(log.Fields{
				"tag":     tag,
				"err":     err,
				"pending": len(c.pendingReports),
			}).Info("Report user traffic failed; will resend")
			return
		}
		log.WithField("tag", tag).Infof("Report %d users traffic", len(r.traffic))
		log.WithField("tag", tag).Debugf("User traffic: %+v", r.traffic)
		c.pendingReports = c.pendingReports[1:]
	}
	c.pendingReports = nil
}
