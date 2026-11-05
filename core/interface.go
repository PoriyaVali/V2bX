package core

import (
	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
)

type AddUsersParams struct {
	Tag   string
	Users []panel.UserInfo
	*panel.NodeInfo
}

type Core interface {
	Start() error
	Close() error
	AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error
	DelNode(tag string) error
	AddUsers(p *AddUsersParams) (added int, err error)
	GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error)
	DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error
	Protocols() []string
	Type() string
}

// NodeRetirer closes a node and returns its final reportable traffic after
// in-flight accounting has completed. An error means teardown did not finish.
type NodeRetirer interface {
	RetireNode(tag string) ([]panel.UserTraffic, error)
}

// NodePreparer is a core that has slow, fallible work to do before a node can
// start - issuing its certificate - and can do it while the node's previous
// listener is still serving. A reload calls it before retiring that listener,
// so a failure leaves the old one up for the next poll to retry, rather than
// the node down until the authority answers. AddNode must still work without
// it, as it does at first start; preparing ahead only moves the slow part.
type NodePreparer interface {
	PrepareNode(tag string, info *panel.NodeInfo, config *conf.Options) error
}
