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
		// Created but never started, so EnableDynamicSpeedLimit did nothing.
		_ = c.dynamicSpeedLimitPeriodic.Start(false)
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
		// Keep the counts we have and carry on: aborting here skipped the user
		// list sync below, so one failed alive poll delayed membership changes.
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("Get alive list failed; keeping the previous counts")
		newA, err = nil, nil
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	if c.closed {
		// Close ran while this poll was talking to the panel.
		return nil
	}
	// A reload that failed part-way left the core out of step with c.info.
	// Rebuild from that config even when the panel now answers "unchanged":
	// the node used to stay out of the core until the panel's config changed
	// again, because the retry looked like a no-op next to what c.info held.
	if newN == nil && c.needsReload && c.info != nil {
		newN = c.info
	}
	// Hot path: if only thresholds/intervals changed, apply them in place and
	// treat the node as unchanged so we skip the disruptive DelNode/re-add
	// (which would drop every active connection). Users/alive still update.
	// Only for a node the core fully reflects - a half-applied one needs the
	// full rebuild below whatever changed.
	if newN != nil && !c.needsReload && c.nodeUp && c.info != nil && onlyHotFieldsChanged(c.info, newN) {
		c.applyHotConfig(newN)
		newN = nil
	}
	if newN != nil {
		c.reloadNode(newN, newU, userListFresh, newA)
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

// reloadNode rebuilds the node in the core around newN. It runs on the
// node-info goroutine with opMu held. Any step that fails leaves needsReload
// set, so the next poll carries on from here instead of trusting a config
// that never made it into the core.
func (c *Controller) reloadNode(newN *panel.NodeInfo, newU []panel.UserInfo, userListFresh bool, newA map[int]int) {
	c.needsReload = true
	c.setInfo(newN)
	tag, l := c.tag, c.limiter
	if l == nil {
		// Never went through Start (only tests drive the monitor like this).
		tag = c.Options.Name
		if len(tag) == 0 {
			tag = c.buildNodeTag(newN)
		}
		var addErr error
		l, addErr = limiter.AddLimiterExclusive(tag, &c.LimitConfig, nil, newA)
		if addErr != nil {
			log.WithFields(log.Fields{"tag": tag, "err": addErr}).Error("Add limiter failed")
			c.apiClient.ResetNodeCache()
			return
		}
		c.setIdentity(tag, l)
	}
	log.WithField("tag", tag).Info("Node changed, reload")

	// The limiter is kept across the reload and brought up to date in place.
	// It used to be rebuilt, and only for nodes without a Name: on a named node
	// a user who joined in the same poll as a config change was never added to
	// it and was refused as unknown until the process restarted; on the others
	// every device registration was thrown away, so a device_limit=1 user
	// reconnecting after the reload was counted against their own device.
	if userListFresh {
		deleted, added := compareUserList(c.userList, newU)
		l.UpdateUser(tag, added, deleted)
		l.UpdateUserLimits(tag, newU)
		c.userList = newU
		c.syncUIDIndex()
	}
	if c.LimitConfig.EnableDynamicSpeedLimit {
		c.trafficMu.Lock()
		c.traffic = make(map[int]int64)
		c.trafficMu.Unlock()
	}
	if newA != nil {
		l.SetAliveList(newA)
	}
	if err := l.UpdateRule(&newN.Rules); err != nil {
		log.WithFields(log.Fields{"tag": tag, "err": err}).Error("Update Rule failed")
		c.apiClient.ResetNodeCache()
		return
	}

	// Remove old node
	if c.nodeUp {
		if err := c.server.DelNode(tag); err != nil {
			// Don't crash the whole process (all other nodes) over one node's
			// reload failure; the next poll retries.
			log.WithFields(log.Fields{"tag": tag, "err": err}).Error("Delete node failed")
			c.apiClient.ResetNodeCache()
			return
		}
		c.nodeUp = false
	}
	// check cert
	if newN.Security == panel.Tls {
		if err := c.requestCert(); err != nil {
			log.WithFields(log.Fields{"tag": tag, "err": err}).Error("Request cert failed")
			c.apiClient.ResetNodeCache()
			return
		}
	}
	// add new node
	if err := c.server.AddNode(tag, newN, c.Options); err != nil {
		// The old node was already removed above, so it's down until the next
		// poll rebuilds it; the other nodes are untouched.
		log.WithFields(log.Fields{"tag": tag, "err": err}).Error("Add node failed")
		c.apiClient.ResetNodeCache()
		return
	}
	c.nodeUp = true
	if _, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      tag,
		Users:    c.userList,
		NodeInfo: newN,
	}); err != nil {
		// needsReload stays set: the next poll takes the node down and brings
		// it back with its users, rather than leaving it up with nobody on it.
		log.WithFields(log.Fields{"tag": tag, "err": err}).Error("Add users failed")
		c.apiClient.ResetNodeCache()
		return
	}
	c.needsReload = false
	c.applyIntervals(newN)
	log.WithField("tag", tag).Infof("Added %d new users", len(c.userList))
}

// applyIntervals restarts the poll and report tasks on the panel's intervals
// when they changed.
func (c *Controller) applyIntervals(newN *panel.NodeInfo) {
	if t := c.nodeInfoMonitorPeriodic; t != nil && newN.PullInterval != 0 && t.Interval != newN.PullInterval {
		t.SetInterval(newN.PullInterval)
		t.Close()
		_ = t.Start(false)
	}
	if t := c.userReportPeriodic; t != nil && newN.PushInterval != 0 && t.Interval != newN.PushInterval {
		t.SetInterval(newN.PushInterval)
		t.Close()
		_ = t.Start(false)
	}
}

func (c *Controller) reportNodeStatusTask() error {
	status, err := serverstatus.GetSystemStatus()
	if err != nil {
		return nil
	}
	if err := c.apiClient.ReportNodeStatus(status); err != nil {
		tag, _, _ := c.state()
		log.WithField("tag", tag).WithError(err).Warn("Report node status failed")
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
	tag, _, l := c.state()
	if l == nil {
		return nil
	}
	expire := time.Now().Add(time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.ExpireTime) * time.Minute)
	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()
	for uid, t := range c.traffic {
		if t >= c.LimitConfig.DynamicSpeedLimitConfig.Traffic {
			uuid, ok := c.uidToUUID[uid]
			if !ok {
				continue
			}
			if err := l.UpdateDynamicSpeedLimit(tag, uuid,
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
//
// It publishes a modified copy rather than editing c.info in place: the report
// goroutine reads the thresholds while this runs.
func (c *Controller) applyHotConfig(newN *panel.NodeInfo) {
	next := *c.info
	next.NodeReportMinTraffic = newN.NodeReportMinTraffic
	next.DeviceOnlineMinTraffic = newN.DeviceOnlineMinTraffic
	if newN.PullInterval != 0 {
		next.PullInterval = newN.PullInterval
	}
	if newN.PushInterval != 0 {
		next.PushInterval = newN.PushInterval
	}
	c.setInfo(&next)
	c.applyIntervals(newN)
	log.WithField("tag", c.tag).Info("Applied hot config (thresholds/intervals) without node reload")
}
