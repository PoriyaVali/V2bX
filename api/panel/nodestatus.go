package panel

import "github.com/PoriyaVali/V2bX/common/serverstatus"

func (c *Client) ReportNodeStatus(status *serverstatus.SystemStatus) error {
	return c.ReportNodeHealth(status, nil)
}

// NodeHealth is what V2bX says about one node in its status report, so the
// panel can show a node V2bX cannot serve without anyone reading the log.
type NodeHealth struct {
	// Serving: the node is in its core and takes connections.
	Serving bool `json:"serving"`
	// Users is how many users the panel's last list gave the node.
	Users int `json:"users"`
	// Error is the current problem, such as a port in use or a certificate
	// that cannot be issued; empty when there is none.
	Error string `json:"error,omitempty"`
}

// ReportNodeHealth sends the server's load with the node's health. Panels
// that do not know the "node" field ignore it.
func (c *Client) ReportNodeHealth(status *serverstatus.SystemStatus, health *NodeHealth) error {
	const path = "/api/v1/server/UniProxy/status"
	body := struct {
		*serverstatus.SystemStatus
		Node *NodeHealth `json:"node,omitempty"`
	}{status, health}
	if health != nil && health.Error != "" {
		// The text reaches the admin page: no token, and a bounded length.
		sent := *health
		sent.Error = redactToken(sent.Error, c.Token)
		if runes := []rune(sent.Error); len(runes) > 300 {
			sent.Error = string(runes[:300])
		}
		body.Node = &sent
	}
	r, err := c.client.R().
		SetBody(body).
		ForceContentType("application/json").
		Post(path)
	return c.checkAcknowledgement(r, path, err)
}
