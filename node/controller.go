package node

import (
	"errors"
	"fmt"
	"sync"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/task"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server                    vCore.Core
	apiClient                 *panel.Client
	tag                       string
	limiter                   *limiter.Limiter
	traffic                   map[int]int64  // UID -> bytes accumulated in the current dynamic-speed window
	uidToUUID                 map[int]string // UID -> UUID snapshot, so SpeedChecker can resolve users without touching userList
	trafficMu                 sync.Mutex     // guards traffic + uidToUUID (accessed by the report and speed-checker goroutines)
	userList                  []panel.UserInfo
	aliveMap                  map[int]int
	info                      *panel.NodeInfo
	reportAccum               map[int][2]int64 // UID -> [up,down] carried over below node_report_min_traffic
	nodeInfoMonitorPeriodic   *task.Task
	userReportPeriodic        *task.Task
	renewCertPeriodic         *task.Task
	dynamicSpeedLimitPeriodic *task.Task
	onlineIpReportPeriodic    *task.Task
	statusReportPeriodic      *task.Task
	*conf.Options
}

// NewController return a Node controller with default parameters.
func NewController(server vCore.Core, api *panel.Client, config *conf.Options) *Controller {
	controller := &Controller{
		server:    server,
		Options:   config,
		apiClient: api,
	}
	return controller
}

// syncUIDIndex rebuilds the UID->UUID lookup that SpeedChecker uses to resolve
// a user without racing on userList (which only the nodeInfoMonitor goroutine
// owns). It is a no-op unless dynamic speed limiting is enabled, so nodes that
// don't use the feature pay nothing. Callers must already own the userList
// (i.e. run on the nodeInfoMonitor goroutine or during Start).
func (c *Controller) syncUIDIndex() {
	if !c.LimitConfig.EnableDynamicSpeedLimit {
		return
	}
	m := make(map[int]string, len(c.userList))
	for i := range c.userList {
		m[c.userList[i].Id] = c.userList[i].Uuid
	}
	c.trafficMu.Lock()
	c.uidToUUID = m
	c.trafficMu.Unlock()
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	// First fetch Node Info
	var err error
	node, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	// Update user
	//
	// A 304 would mean an etag survived into a fresh start, which cannot happen
	// today - but reading it as a failure would make the node refuse to boot
	// over a reply that only says "nothing changed". Start empty instead and let
	// the first monitor pass fill the list in.
	c.userList, err = c.apiClient.GetUserList()
	if err != nil && !errors.Is(err, panel.ErrUserListNotModified) {
		return fmt.Errorf("get user list error: %s", err)
	}
	// An empty user list is a legitimate state, not a startup failure. A node
	// can legitimately have nobody on it: a tier nobody has bought yet, or one
	// whose members are all currently ineligible (expired, out of data, or - for
	// a metered tier - out of balance). Treating that as fatal meant the LAST
	// eligible user leaving took the node down, and because one process serves
	// several nodes it took the unrelated ones with it: a paid tier emptying out
	// cost 340 users on a different node ~28 minutes of downtime.
	//
	// Start with nobody instead; nodeInfoMonitor adds users as soon as the panel
	// returns any. AddUsers over an empty slice is a no-op in every core.
	if len(c.userList) == 0 {
		log.WithField("tag", c.buildNodeTag(node)).
			Info("No eligible users yet; starting the node empty and waiting for the panel")
	}
	c.aliveMap, err = c.apiClient.GetUserAlive()
	if err != nil {
		return fmt.Errorf("failed to get user alive list: %s", err)
	}
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(node)
	} else {
		c.tag = c.Options.Name
	}

	// add limiter
	l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
	// add rule limiter
	if err = l.UpdateRule(&node.Rules); err != nil {
		return fmt.Errorf("update rule error: %s", err)
	}
	c.limiter = l
	if node.Security == panel.Tls {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(c.tag, node, c.Options)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: node,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	log.WithField("tag", c.tag).Infof("Added %d new users", added)
	c.info = node
	c.syncUIDIndex()
	c.startTasks(node)
	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	limiter.DeleteLimiter(c.tag)
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	if c.dynamicSpeedLimitPeriodic != nil {
		c.dynamicSpeedLimitPeriodic.Close()
	}
	if c.onlineIpReportPeriodic != nil {
		c.onlineIpReportPeriodic.Close()
	}
	err := c.server.DelNode(c.tag)
	if err != nil {
		return fmt.Errorf("del node error: %s", err)
	}
	return nil
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiClient.APIHost, node.Type, node.Id)
}
