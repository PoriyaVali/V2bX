package panel

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

// Debug set the client debug for client
func (c *Client) Debug() {
	c.client.SetDebug(true)
}

func (c *Client) assembleURL(path string) string {
	return strings.TrimRight(c.APIHost, "/") + path
}

// ErrNodeNotFound is the panel saying it has no node with this type and ID:
// V2board and Irboard answer every node API call for a deleted node with
// "server is not exist". It is never inferred from a bare 404, which a
// misconfigured ApiHost or a maintenance page also returns.
var ErrNodeNotFound = errors.New("the panel has no such node (deleted?)")

func (c *Client) checkResponse(res *resty.Response, path string, err error) error {
	if err != nil {
		return fmt.Errorf("request %s failed: %s", c.assembleURL(path), redactToken(err.Error(), c.Token))
	}
	if res == nil {
		return fmt.Errorf("request %s failed: nil response", c.assembleURL(path))
	}
	if res.StatusCode() < 200 || res.StatusCode() >= 300 {
		body := res.Body()
		// Include enough overlap to redact a token crossing the log boundary.
		if limit := 1024 + 3*len(c.Token); len(body) > limit {
			body = body[:limit]
		}
		if strings.Contains(strings.ToLower(string(body)), "server is not exist") {
			return fmt.Errorf("request %s failed: HTTP %d: %w", c.assembleURL(path), res.StatusCode(), ErrNodeNotFound)
		}
		return fmt.Errorf("request %s failed: HTTP %d: %.1024s", c.assembleURL(path), res.StatusCode(), redactToken(string(body), c.Token))
	}
	return nil
}

func redactToken(value, token string) string {
	if token == "" {
		return value
	}
	for _, secret := range []string{url.QueryEscape(token), token} {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

// Resty also logs transport retry errors, which can contain the query token.
type panelLogger struct{ token string }

func (l panelLogger) Errorf(format string, values ...any) {
	log.Error(redactToken(fmt.Sprintf(format, values...), l.token))
}
func (l panelLogger) Warnf(format string, values ...any) {
	log.Warn(redactToken(fmt.Sprintf(format, values...), l.token))
}
func (l panelLogger) Debugf(format string, values ...any) {
	log.Debug(redactToken(fmt.Sprintf(format, values...), l.token))
}

// A proxy login page or {"data":false} with HTTP 200 did not accept a report.
// Only discard queued traffic (or an online snapshot) after Irboard's receipt.
func (c *Client) checkAcknowledgement(res *resty.Response, path string, err error) error {
	if err = c.checkResponse(res, path, err); err != nil {
		return err
	}
	var receipt struct {
		Data bool `json:"data"`
	}
	if err := json.Unmarshal(res.Body(), &receipt); err != nil {
		return fmt.Errorf("request %s: invalid report acknowledgement: %s", c.assembleURL(path), redactToken(err.Error(), c.Token))
	}
	if !receipt.Data {
		return fmt.Errorf("request %s: report was not acknowledged", c.assembleURL(path))
	}
	return nil
}
