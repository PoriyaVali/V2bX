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
	server    vCore.Core
	apiClient *panel.Client
	// stateMu guards tag, limiter and info. The node-info goroutine replaces
	// them while the report, speed-check and status goroutines read them; they
	// used to be plain fields shared between those goroutines, a data race the
	// race detector reported on every node reload. Readers go through state().
	stateMu                   sync.RWMutex
	tag                       string
	limiter                   *limiter.Limiter
	info                      *panel.NodeInfo
	traffic                   map[int]int64  // UID -> bytes accumulated in the current dynamic-speed window
	uidToUUID                 map[int]string // UID -> UUID snapshot, so SpeedChecker can resolve users without touching userList
	trafficMu                 sync.Mutex     // guards traffic + uidToUUID (accessed by the report and speed-checker goroutines)
	userList                  []panel.UserInfo
	aliveMap                  map[int]int
	reportAccum               map[int][2]int64 // UID -> [up,down] carried over below node_report_min_traffic
	pendingReports            []pendingReport  // traffic batches not yet accepted by the panel, oldest first
	nodeInfoMonitorPeriodic   *task.Task
	userReportPeriodic        *task.Task
	renewCertPeriodic         *task.Task
	dynamicSpeedLimitPeriodic *task.Task
	onlineIpReportPeriodic    *task.Task
	statusReportPeriodic      *task.Task
	// opMu serialises what the node-info goroutine does to the core with
	// Close, so a reload that is under way cannot put the node back into the
	// core after Close has taken it out. It also guards the three flags below.
	opMu sync.Mutex
	// nodeUp: the node is registered in the core right now.
	nodeUp bool
	// needsReload: the core does not reflect info/userList - a reload failed
	// part-way - and the next poll must rebuild the node whatever the panel
	// says. Without it a failed reload looked "unchanged" on the next poll and
	// the node stayed out of the core until the panel's config changed again.
	needsReload bool
	closed      bool
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

// state returns the node's tag, current node info and limiter. Safe from any
// goroutine.
func (c *Controller) state() (string, *panel.NodeInfo, *limiter.Limiter) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.tag, c.info, c.limiter
}

// setInfo publishes the node info. Only the goroutine that owns the node's
// lifecycle (Start, then nodeInfoMonitor) calls it, so that goroutine may keep
// reading c.info directly.
func (c *Controller) setInfo(info *panel.NodeInfo) {
	c.stateMu.Lock()
	c.info = info
	c.stateMu.Unlock()
}

// setIdentity publishes the tag and limiter; same ownership rule as setInfo.
func (c *Controller) setIdentity(tag string, l *limiter.Limiter) {
	c.stateMu.Lock()
	c.tag = tag
	c.limiter = l
	c.stateMu.Unlock()
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
func (c *Controller) Start() (err error) {
	// First fetch Node Info
	node, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	if node == nil {
		// A 304 or an unchanged body. Only possible if this client has polled
		// before; the retry loop builds a fresh one for exactly this reason.
		return fmt.Errorf("get node info error: panel sent no node info")
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
		// Not a reason to keep the node down: with no counts yet every device
		// is admitted, and the next poll fills them in.
		log.WithField("err", err).Warn("Get alive list failed; starting without device counts")
		c.aliveMap, err = make(map[int]int), nil
	}
	tag := c.Options.Name
	if len(tag) == 0 {
		tag = c.buildNodeTag(node)
	}

	// add limiter
	l, err := limiter.AddLimiterExclusive(tag, &c.LimitConfig, c.userList, c.aliveMap)
	if err != nil {
		return err
	}
	c.setIdentity(tag, l)
	// A start that fails part-way must leave nothing behind: the node is
	// retried, and a leftover limiter or a node still registered in the core
	// would make the next attempt fail with "already exists" forever.
	nodeAdded := false
	defer func() {
		if err == nil {
			return
		}
		if nodeAdded {
			if derr := c.server.DelNode(tag); derr != nil {
				log.WithField("tag", tag).Error("Undo AddNode after failed start: ", derr)
			}
		}
		limiter.DeleteLimiterIf(tag, l)
	}()
	// add rule limiter
	if err = l.UpdateRule(&node.Rules); err != nil {
		return fmt.Errorf("update rule error: %s", err)
	}
	if node.Security == panel.Tls {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(tag, node, c.Options)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	nodeAdded = true
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      tag,
		Users:    c.userList,
		NodeInfo: node,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	log.WithField("tag", tag).Infof("Added %d new users", added)
	c.setInfo(node)
	c.opMu.Lock()
	c.nodeUp = true
	c.opMu.Unlock()
	c.syncUIDIndex()
	c.startTasks(node)
	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	// First wait out a reload that is already running and make sure no later
	// one starts: the node must not come back into the core after this. It has
	// to come before the tasks are stopped, so a late poll cannot mutate state
	// during teardown.
	c.opMu.Lock()
	c.closed = true
	up := c.nodeUp
	c.nodeUp = false
	c.opMu.Unlock()
	tasks := []*task.Task{
		c.nodeInfoMonitorPeriodic,
		c.userReportPeriodic,
		c.renewCertPeriodic,
		c.dynamicSpeedLimitPeriodic,
		c.onlineIpReportPeriodic,
		// This one was left out, so every config reload and every retried start
		// left a goroutine behind that reported server status for the rest of
		// the process's life.
		c.statusReportPeriodic,
	}
	for _, t := range tasks {
		if t != nil {
			t.Close()
		}
	}
	// Join every in-flight Execute before deleting the node/core state it uses.
	for _, t := range tasks {
		if t != nil {
			t.Wait()
		}
	}
	// The report task has stopped; this flush has sole ownership of its
	// queue and accumulator. Include sub-threshold bytes before teardown.
	if c.apiClient != nil {
		if len(c.reportAccum) > 0 {
			c.queueTrafficReport(c.applyReportMinTraffic(nil, 0))
		}
		if len(c.pendingReports) > 0 {
			c.flushTrafficReports()
		}
	}
	tag, _, _ := c.state()
	var err error
	if up {
		if derr := c.server.DelNode(tag); derr != nil {
			err = fmt.Errorf("del node error: %s", derr)
		}
	}
	// The limiter goes after the node, not before: a connection arriving in
	// between would find no limiter - hysteria2 treated that as fatal, sing
	// let the connection through unlimited and uncounted.
	limiter.DeleteLimiterIf(tag, c.limiter)
	return err
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiClient.APIHost, node.Type, node.Id)
}
