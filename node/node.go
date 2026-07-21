package node

import (
	"fmt"
	"strings"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	log "github.com/sirupsen/logrus"
)

type Node struct {
	controllers []*Controller
}

func New() *Node {
	return &Node{}
}

func (n *Node) Start(nodes []conf.NodeConfig, core vCore.Core) error {
	n.controllers = make([]*Controller, len(nodes))
	// One process usually serves several nodes. A failure on one of them - a
	// panel that is briefly unreachable, a certificate that will not issue - used
	// to abort this loop and bring the whole process down, so a problem confined
	// to a single node disconnected every user on every OTHER node it served.
	// Start what can be started, report the rest, and only give up if nothing
	// came up at all.
	var started int
	var failures []string
	for i := range nodes {
		desc := fmt.Sprintf("%s-%s-%d",
			nodes[i].ApiConfig.APIHost,
			nodes[i].ApiConfig.NodeType,
			nodes[i].ApiConfig.NodeID)
		p, err := panel.New(&nodes[i].ApiConfig)
		if err != nil {
			failures = append(failures, fmt.Sprintf("[%s] %s", desc, err))
			log.WithField("node", desc).Error("Build panel client failed: ", err)
			continue
		}
		// Register controller service
		n.controllers[i] = NewController(core, p, &nodes[i].Options)
		if err = n.controllers[i].Start(); err != nil {
			n.controllers[i] = nil
			failures = append(failures, fmt.Sprintf("[%s] %s", desc, err))
			log.WithField("node", desc).Error("Start node controller failed: ", err)
			continue
		}
		started++
	}
	if started == 0 {
		return fmt.Errorf("no node could be started: %s", strings.Join(failures, "; "))
	}
	if len(failures) > 0 {
		log.Warnf("%d of %d nodes started; the rest keep retrying: %s",
			started, len(nodes), strings.Join(failures, "; "))
	}
	return nil
}

func (n *Node) Close() {
	for _, c := range n.controllers {
		err := c.Close()
		if err != nil {
			panic(err)
		}
	}
	n.controllers = nil
}
