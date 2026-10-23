package panel

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/go-resty/resty/v2"
)

// DiscoverNodeConfigs probes only the authenticated, read-only config endpoint.
// IDs are local to protocol tables in Irboard: all matches must be returned,
// rather than guessing the first successful protocol. Each request owns its
// client/cache; at most three requests run at once and probes are not retried.
func DiscoverNodeConfigs(ctx context.Context, config conf.ApiConfig, types []string) ([]*NodeInfo, error) {
	results := make([]*NodeInfo, len(types))
	errors := make([]error, len(types))
	uncertain := make([]bool, len(types))
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
				errors[i] = ctx.Err()
				return
			}
			candidate := config
			candidate.NodeType = protocol
			client, err := New(&candidate)
			if err != nil {
				errors[i] = err
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
				return nil
			})
			info, err := client.GetNodeInfoContext(ctx)
			if err != nil {
				errors[i] = err
				uncertain[i] = !missing
				return
			}
			if info == nil || info.Common == nil || info.Common.ServerPort < 1 || info.Common.ServerPort > 65535 {
				errors[i] = fmt.Errorf("incomplete %s node configuration", protocol)
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
			return nil, fmt.Errorf("node discovery incomplete; cannot safely choose a protocol: %w", errors[i])
		}
	}
	if len(found) == 0 {
		for _, err := range errors {
			if err != nil {
				return nil, fmt.Errorf("no node found for this core; check the ID, core and API credentials: %w", err)
			}
		}
		return nil, fmt.Errorf("no node found for this core")
	}
	return found, nil
}
