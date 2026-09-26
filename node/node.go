package node

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	log "github.com/sirupsen/logrus"
)

// How long a node that failed to start waits before trying again, doubling up
// to the ceiling. Variables so tests can shorten them.
var (
	retryInitialDelay = 10 * time.Second
	retryMaxDelay     = 5 * time.Minute
)

type Node struct {
	mu          sync.Mutex
	controllers []*Controller
	stop        chan struct{}
	retries     sync.WaitGroup
}

func New() *Node {
	return &Node{}
}

func nodeDesc(c *conf.NodeConfig) string {
	return fmt.Sprintf("%s-%s-%d", c.ApiConfig.APIHost, c.ApiConfig.NodeType, c.ApiConfig.NodeID)
}

func (n *Node) Start(nodes []conf.NodeConfig, core vCore.Core) error {
	n.mu.Lock()
	n.controllers = make([]*Controller, len(nodes))
	n.stop = make(chan struct{})
	stop := n.stop
	n.mu.Unlock()
	// One process usually serves several nodes. A failure on one of them - a
	// panel that is briefly unreachable, a certificate that will not issue - used
	// to abort this loop and bring the whole process down, so a problem confined
	// to a single node disconnected every user on every OTHER node it served.
	// Start what can be started and keep retrying the rest in the background.
	//
	// The retry is new. A node that failed here used to be dropped for the life
	// of the process while the log claimed it would "keep retrying": nothing
	// did, so a node that booted during a panel hiccup stayed down until the
	// next restart.
	var started, retrying int
	var failures []string
	for i := range nodes {
		desc := nodeDesc(&nodes[i])
		p, err := panel.New(&nodes[i].ApiConfig)
		if err != nil {
			// A bad node type or similar: the config itself is wrong, and
			// retrying the same config cannot fix it.
			failures = append(failures, fmt.Sprintf("[%s] %s", desc, err))
			log.WithField("node", desc).Error("Build panel client failed: ", err)
			continue
		}
		c := NewController(core, p, &nodes[i].Options)
		if err = c.Start(); err != nil {
			failures = append(failures, fmt.Sprintf("[%s] %s", desc, err))
			log.WithField("node", desc).Error("Start node controller failed, retrying in the background: ", err)
			n.retryStart(i, &nodes[i], core, stop)
			retrying++
			continue
		}
		n.mu.Lock()
		n.controllers[i] = c
		n.mu.Unlock()
		started++
	}
	if started == 0 && retrying == 0 {
		return fmt.Errorf("no node could be started: %s", strings.Join(failures, "; "))
	}
	if len(failures) > 0 {
		log.Warnf("%d of %d nodes started, %d retrying: %s",
			started, len(nodes), retrying, strings.Join(failures, "; "))
	}
	return nil
}

// retryStart keeps trying to start node i until it comes up or the Node is
// closed. Every attempt builds a fresh panel client: a client that already
// holds an ETag gets a 304 for the node and for the user list, and a
// controller started from those would come up with no node info and nobody on
// it - and then never add anyone, because every later poll says "unchanged".
func (n *Node) retryStart(i int, cfg *conf.NodeConfig, core vCore.Core, stop chan struct{}) {
	desc := nodeDesc(cfg)
	n.retries.Add(1)
	go func() {
		defer n.retries.Done()
		delay := retryInitialDelay
		for attempt := 1; ; attempt++ {
			select {
			case <-stop:
				return
			case <-time.After(delay):
			}
			if delay *= 2; delay > retryMaxDelay {
				delay = retryMaxDelay
			}
			p, err := panel.New(&cfg.ApiConfig)
			if err != nil {
				log.WithField("node", desc).Error("Build panel client failed, giving up: ", err)
				return
			}
			c := NewController(core, p, &cfg.Options)
			if err = c.Start(); err != nil {
				log.WithField("node", desc).Warnf("Start attempt %d failed, next in %s: %s", attempt, delay, err)
				continue
			}
			n.mu.Lock()
			select {
			case <-stop:
				// Closed while this attempt was running: undo it rather than
				// leave a node registered in a core that is being shut down.
				n.mu.Unlock()
				if err := c.Close(); err != nil {
					log.WithField("node", desc).Error("Close late-started node failed: ", err)
				}
				return
			default:
			}
			n.controllers[i] = c
			n.mu.Unlock()
			log.WithField("node", desc).Infof("Node started on attempt %d", attempt)
			return
		}
	}()
}

func (n *Node) Close() {
	n.mu.Lock()
	if n.stop != nil {
		close(n.stop)
		n.stop = nil
	}
	controllers := n.controllers
	n.controllers = nil
	n.mu.Unlock()
	// Let in-flight retries finish or back out before the core goes away.
	n.retries.Wait()
	for _, c := range controllers {
		// A slot stays nil for a node that never started. Calling Close on it
		// dereferenced nil and crashed the process on the next config reload.
		if c == nil {
			continue
		}
		// Log and carry on: one node failing to close must not stop the others
		// from closing (this used to panic).
		if err := c.Close(); err != nil {
			log.WithField("tag", c.tag).Error("Close node failed: ", err)
		}
	}
}
