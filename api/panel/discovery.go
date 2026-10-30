package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/go-resty/resty/v2"
)

// ErrNoNode is a discovery that found no node of the probed protocols.
var ErrNoNode = errors.New("no node found for this core")

// DiscoverNodeConfigs probes only the authenticated, read-only config endpoint.
// IDs are local to protocol tables in Irboard: all matches must be returned,
// rather than guessing the first successful protocol. Each request owns its
// client/cache; at most three requests run at once and probes are not retried.
//
// Irboard answers 409 for a child node and 501 for a managed protocol's node
// without a multi-user server (an external service). Such a node exists but
// cannot be served under this ID, so it is no candidate; it does not make the
// discovery of another protocol's node with the same ID uncertain.
func DiscoverNodeConfigs(ctx context.Context, config conf.ApiConfig, types []string) ([]*NodeInfo, error) {
	results := make([]*NodeInfo, len(types))
	failures := make([]error, len(types))
	uncertain := make([]bool, len(types))
	declined := make([]string, len(types))
	semaphore := make(chan struct{}, 3)
	var workers sync.WaitGroup
	for i, protocol := range types {
		workers.Add(1)
		go func() {
			defer workers.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				failures[i] = ctx.Err()
				return
			}
			candidate := config
			candidate.NodeType = protocol
			client, err := New(&candidate)
			if err != nil {
				failures[i] = err
				uncertain[i] = true
				return
			}
			defer client.client.GetClient().CloseIdleConnections()
			client.client.SetRetryCount(0)
			client.client.SetResponseBodyLimit(4 << 20)
			missing := false
			client.client.OnAfterResponse(func(_ *resty.Client, response *resty.Response) error {
				missing = response.StatusCode() == http.StatusNotFound ||
					(response.StatusCode() == http.StatusInternalServerError && strings.Contains(strings.ToLower(string(response.Body())), "server is not exist"))
				if response.StatusCode() == http.StatusConflict || response.StatusCode() == http.StatusNotImplemented {
					declined[i] = redactToken(panelMessage(response.Body()), config.Key)
				}
				return nil
			})
			info, err := client.GetNodeInfoContext(ctx)
			if err != nil {
				failures[i] = err
				uncertain[i] = !missing && declined[i] == ""
				return
			}
			if info == nil || info.Common == nil || info.Common.ServerPort < 1 || info.Common.ServerPort > 65535 {
				failures[i] = fmt.Errorf("incomplete %s node configuration", protocol)
				uncertain[i] = true
				return
			}
			results[i] = info
		}()
	}
	workers.Wait()
	var found []*NodeInfo
	seen := make(map[string]bool)
	for _, info := range results {
		if info != nil && !seen[info.Type] {
			found = append(found, info)
			seen[info.Type] = true
		}
	}
	// An unfinished discovery cannot establish that one protocol is unique.
	if ctx.Err() != nil {
		return nil, fmt.Errorf("node discovery incomplete: %w", ctx.Err())
	}
	for i, incomplete := range uncertain {
		if incomplete {
			return nil, fmt.Errorf("node discovery incomplete; cannot safely choose a protocol: %w", failures[i])
		}
	}
	if len(found) == 0 {
		var reasons []string
		for i, reason := range declined {
			if reason != "" {
				reasons = append(reasons, fmt.Sprintf("the %s node with this ID cannot be served: %s", types[i], reason))
			}
		}
		if len(reasons) > 0 {
			return nil, fmt.Errorf("%w; %s", ErrNoNode, strings.Join(reasons, "; "))
		}
		for _, err := range failures {
			if err != nil {
				return nil, fmt.Errorf("%w; check the ID, core and API credentials: %w", ErrNoNode, err)
			}
		}
		return nil, ErrNoNode
	}
	return found, nil
}

// panelMessage is the message of a panel error reply, which Irboard sends as
// JSON with its non-ASCII text escaped.
func panelMessage(body []byte) string {
	var reply struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &reply) == nil && strings.TrimSpace(reply.Message) != "" {
		return strings.TrimSpace(reply.Message)
	}
	if len(body) > 256 {
		body = body[:256]
	}
	return strings.TrimSpace(string(body))
}
