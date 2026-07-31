package node

import (
	"errors"
	"reflect"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/serverstatus"
	"github.com/PoriyaVali/V2bX/common/task"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) startTasks(node *panel.NodeInfo) {
	// fetch node info task
	c.nodeInfoMonitorPeriodic = &task.Task{
		Interval: node.PullInterval,
		Execute:  c.nodeInfoMonitor,
	}
	// fetch user list task
	c.userReportPeriodic = &task.Task{
		Interval: node.PushInterval,
		Execute:  c.reportUserTrafficTask,
	}
	log.WithField("tag", c.tag).Info("Start monitor node status")
	// delay to start nodeInfoMonitor
	_ = c.nodeInfoMonitorPeriodic.Start(false)
	log.WithField("tag", c.tag).Info("Start report node status")
	_ = c.userReportPeriodic.Start(false)
	if node.Security == panel.Tls {
		switch c.CertConfig.CertMode {
		case "none", "", "file", "self":
		default:
			c.renewCertPeriodic = &task.Task{
				// Check every 6h (cheap: only reads/parses the cert; hits
				// ACME only when <30 days remain). Gives up to 4 renewal
				// retries/day if one fails near expiry.
				Interval: time.Hour * 6,
				Execute:  c.renewCertTask,
			}
			log.WithField("tag", c.tag).Info("Start renew cert")
			// delay to start renewCert
			_ = c.renewCertPeriodic.Start(true)
		}
	}
	// report server status every 60s
	c.statusReportPeriodic = &task.Task{
		Interval: time.Second * 60,
		Execute:  c.reportNodeStatusTask,
	}
	_ = c.statusReportPeriodic.Start(false)

	if c.LimitConfig.EnableDynamicSpeedLimit {
		c.traffic = make(map[int]int64)
		c.dynamicSpeedLimitPeriodic = &task.Task{
			Interval: time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.Periodic) * time.Second,
			Execute:  c.SpeedChecker,
		}
		log.Printf("[%s: %d] Start dynamic speed limit", c.apiClient.NodeType, c.apiClient.NodeId)
	}
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// get node info
	newN, err := c.apiClient.GetNodeInfo()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get node info failed")
		return nil
	}
	// get user info
	//
	// userListFresh separates "the panel sent a list" from "the panel said
	// nothing changed". Only the first lets us act on membership below - and
	// crucially, a fresh list that is EMPTY is an answer, not a non-answer: it
	// means nobody is authorised here any more. Testing len(newU) instead
	// collapsed those two cases and left cut-off users connected.
	newU, err := c.apiClient.GetUserList()
	userListFresh := true
	if errors.Is(err, panel.ErrUserListNotModified) {
		userListFresh, newU, err = false, nil, nil
	}
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get user list failed")
		return nil
	}
	// get user alive
	newA, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get alive list failed")
		return nil
	}
	// Hot path: if only thresholds/intervals changed, apply them in place and
	// treat the node as unchanged so we skip the disruptive DelNode/re-add
	// (which would drop every active connection). Users/alive still update.
	if newN != nil && c.info != nil && onlyHotFieldsChanged(c.info, newN) {
		c.applyHotConfig(newN)
		newN = nil
	}
	if newN != nil {
		c.info = newN
		// nodeInfo changed
		//
		// Same distinction as below: adopt the list whenever the panel actually
		// sent one, including an empty one. A nil check would not do - a reply
		// carrying no users decodes to a nil slice, so the node would rebuild
		// itself around the previous membership and re-add users the panel had
		// just dropped.
		if userListFresh {
			c.userList = newU
			c.syncUIDIndex()
		}
		if c.LimitConfig.EnableDynamicSpeedLimit {
			c.trafficMu.Lock()
			c.traffic = make(map[int]int64)
			c.trafficMu.Unlock()
		}
		// Remove old node
		log.WithField("tag", c.tag).Info("Node changed, reload")
		err = c.server.DelNode(c.tag)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Delete node failed")
			// Don't crash the whole process (all other nodes) over one node's
			// reload failure; force a re-fetch so this node retries next cycle.
			c.apiClient.ResetNodeCache()
			return nil
		}

		// Update limiter
		if len(c.Options.Name) == 0 {
			c.tag = c.buildNodeTag(newN)
			// Remove Old limiter
			limiter.DeleteLimiter(c.tag)
			// Add new Limiter
			l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, newA)
			c.limiter = l
		}
		// update alive list
		if newA != nil {
			c.limiter.SetAliveList(newA)
		}
		// Update rule
		err = c.limiter.UpdateRule(&newN.Rules)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Update Rule failed")
			c.apiClient.ResetNodeCache()
			return nil
		}

		// check cert
		if newN.Security == panel.Tls {
			err = c.requestCert()
			if err != nil {
				log.WithFields(log.Fields{
					"tag": c.tag,
					"err": err,
				}).Error("Request cert failed")
				c.apiClient.ResetNodeCache()
				return nil
			}
		}
		// add new node
		err = c.server.AddNode(c.tag, newN, c.Options)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add node failed")
			// Graceful: keep other nodes alive and retry this node next cycle
			// (the old node was already removed above, so it's down until retry).
			c.apiClient.ResetNodeCache()
			return nil
		}
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			Users:    c.userList,
			NodeInfo: newN,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add users failed")
			c.apiClient.ResetNodeCache()
			return nil
		}
		// Check interval
		if c.nodeInfoMonitorPeriodic.Interval != newN.PullInterval &&
			newN.PullInterval != 0 {
			c.nodeInfoMonitorPeriodic.Interval = newN.PullInterval
			c.nodeInfoMonitorPeriodic.Close()
			_ = c.nodeInfoMonitorPeriodic.Start(false)
		}
		if c.userReportPeriodic.Interval != newN.PushInterval &&
			newN.PushInterval != 0 {
			c.userReportPeriodic.Interval = newN.PushInterval
			c.userReportPeriodic.Close()
			_ = c.userReportPeriodic.Start(false)
		}
		log.WithField("tag", c.tag).Infof("Added %d new users", len(c.userList))
		// exit
		return nil
	}
	// update alive list
	if newA != nil {
		c.limiter.SetAliveList(newA)
	}
	// node no changed, check users
	if !userListFresh {
		return nil
	}
	deleted, added := compareUserList(c.userList, newU)
	if len(deleted) > 0 {
		// have deleted users
		err = c.server.DelUsers(deleted, c.tag, c.info)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Delete users failed")
			return nil
		}
	}
	if len(added) > 0 {
		// have added users
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			NodeInfo: c.info,
			Users:    added,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add users failed")
			return nil
		}
	}
	if len(added) > 0 || len(deleted) > 0 {
		// update Limiter membership
		c.limiter.UpdateUser(c.tag, added, deleted)
		// clear traffic record
		if c.LimitConfig.EnableDynamicSpeedLimit {
			c.trafficMu.Lock()
			for i := range deleted {
				delete(c.traffic, deleted[i].Id)
			}
			c.trafficMu.Unlock()
		}
	}
	// Speed/device limits can change without membership changing, and the panel
	// pushes them on every /user poll — sync them in place so an admin's edit
	// lands within one pull interval instead of waiting for a node reload. Cheap
	// (one sync.Map load per user) and it never disturbs a live connection.
	c.limiter.UpdateUserLimits(c.tag, newU)
	// One core enforces its limits itself rather than through the limiter, so
	// the line above never reaches it: an admin's change would only apply to
	// users who joined afterwards, and a subscriber whose plan changed would
	// keep their old speed indefinitely. Cores that read the limiter do not
	// implement this and are untouched.
	if up, ok := c.server.(interface {
		UpdateUserLimits(tag string, users []panel.UserInfo)
	}); ok {
		up.UpdateUserLimits(c.tag, newU)
	}
	c.userList = newU
	c.syncUIDIndex()
	if len(added)+len(deleted) != 0 {
		log.WithField("tag", c.tag).
			Infof("%d user deleted, %d user added", len(deleted), len(added))
	}
	return nil
}

func (c *Controller) reportNodeStatusTask() error {
	status, err := serverstatus.GetSystemStatus()
	if err != nil {
		return nil
	}
	if err := c.apiClient.ReportNodeStatus(status); err != nil {
		log.WithField("tag", c.tag).WithError(err).Warn("Report node status failed")
	}
	return nil
}

// SpeedChecker runs every DynamicSpeedLimitConfig.Periodic seconds. It throttles
// any user whose traffic accumulated by reportUserTrafficTask during this window
// crossed the configured threshold, then resets the accumulator so the next
// window measures the rate afresh (rather than lifetime totals). The accumulator
// is keyed by UID; UID->UUID comes from the lock-protected snapshot so we never
// touch userList (owned by the nodeInfoMonitor goroutine) from here.
func (c *Controller) SpeedChecker() error {
	expire := time.Now().Add(time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.ExpireTime) * time.Minute)
	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()
	for uid, t := range c.traffic {
		if t >= c.LimitConfig.DynamicSpeedLimitConfig.Traffic {
			uuid, ok := c.uidToUUID[uid]
			if !ok {
				continue
			}
			if err := c.limiter.UpdateDynamicSpeedLimit(c.tag, uuid,
				c.LimitConfig.DynamicSpeedLimitConfig.SpeedLimit, expire); err != nil {
				log.WithField("err", err).Error("Update dynamic speed limit failed")
			}
		}
	}
	// Reset for the next window.
	c.traffic = make(map[int]int64)
	return nil
}

// onlyHotFieldsChanged reports whether newN differs from cur only in the
// "hot" fields that can be applied live (report/device thresholds and the
// push/pull intervals). If every other field is identical, we can update
// those in place instead of tearing the node down. reflect.DeepEqual is
// exact, so a cold-field change can never be mistaken for hot-only.
func onlyHotFieldsChanged(cur, newN *panel.NodeInfo) bool {
	x, y := *cur, *newN // shallow copies; pointers are followed by DeepEqual
	x.NodeReportMinTraffic, y.NodeReportMinTraffic = 0, 0
	x.DeviceOnlineMinTraffic, y.DeviceOnlineMinTraffic = 0, 0
	x.PushInterval, y.PushInterval = 0, 0
	x.PullInterval, y.PullInterval = 0, 0
	return reflect.DeepEqual(x, y)
}

// applyHotConfig updates the live thresholds and (if changed) the task
// intervals without reloading the node, so active connections are untouched.
func (c *Controller) applyHotConfig(newN *panel.NodeInfo) {
	c.info.NodeReportMinTraffic = newN.NodeReportMinTraffic
	c.info.DeviceOnlineMinTraffic = newN.DeviceOnlineMinTraffic
	if c.nodeInfoMonitorPeriodic != nil && newN.PullInterval != 0 &&
		c.nodeInfoMonitorPeriodic.Interval != newN.PullInterval {
		c.info.PullInterval = newN.PullInterval
		c.nodeInfoMonitorPeriodic.Interval = newN.PullInterval
		c.nodeInfoMonitorPeriodic.Close()
		_ = c.nodeInfoMonitorPeriodic.Start(false)
	}
	if c.userReportPeriodic != nil && newN.PushInterval != 0 &&
		c.userReportPeriodic.Interval != newN.PushInterval {
		c.info.PushInterval = newN.PushInterval
		c.userReportPeriodic.Interval = newN.PushInterval
		c.userReportPeriodic.Close()
		_ = c.userReportPeriodic.Start(false)
	}
	log.WithField("tag", c.tag).Info("Applied hot config (thresholds/intervals) without node reload")
}
