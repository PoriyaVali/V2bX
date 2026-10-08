package sing

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/PoriyaVali/V2bX/conf"
	"github.com/sagernet/sing-box/option"
)

func processFallback(c *conf.Options, fallbackForALPN map[string]*option.ServerOptions) error {
	for k, v := range c.SingOptions.FallBackConfigs.FallBackForALPN {
		fallbackPort, err := strconv.ParseUint(v.ServerPort, 10, 16)
		if err != nil {
			return fmt.Errorf("unable to parse fallbackForALPN server port error: %s", err)
		}
		fallbackForALPN[k] = &option.ServerOptions{Server: v.Server, ServerPort: uint16(fallbackPort)}
	}
	return nil
}

// configPort reads a port number from node or panel config.
//
// These fields used to go through strconv.Atoi and uint16(), which wraps
// without a word: 70000 became 4464, a port nobody configured that still looks
// valid. An empty or non-numeric value keeps meaning 0, as it always has; a
// number that does not fit in a port is now an error.
func configPort(s string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("%q is not a port (0-65535)", s)
		}
		return 0, nil
	}
	return uint16(v), nil
}

// earlyDataSize reads the websocket "ed" query parameter. Anything that is not
// a whole number that fits in uint32 means no early data, rather than a
// negative value wrapping round to four gigabytes.
func earlyDataSize(s string) uint32 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}
