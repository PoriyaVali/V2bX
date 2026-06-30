package panel

import "github.com/PoriyaVali/V2bX/common/serverstatus"

func (c *Client) ReportNodeStatus(status *serverstatus.SystemStatus) error {
	const path = "/api/v1/server/UniProxy/status"
	r, err := c.client.R().
		SetBody(status).
		ForceContentType("application/json").
		Post(path)
	return c.checkResponse(r, path, err)
}
