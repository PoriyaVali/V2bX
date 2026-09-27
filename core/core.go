package core

import (
	"errors"

	"github.com/PoriyaVali/V2bX/conf"
)

var (
	cores = map[string]func(c *conf.CoreConfig) (Core, error){}
)

func NewCore(c []conf.CoreConfig) (Core, error) {
	if len(c) == 0 {
		return nil, errors.New("no have vail core")
	}
	// Always through the selector, one core or several. A lone core used to be
	// handed out directly, which skipped what the selector does for every node
	// - resolving which core it belongs to and parsing that core's options -
	// so a node config without "Core" reached the core with its options unset
	// and crashed it on a nil pointer. The lookup here was also case-sensitive
	// where the selector's is not.
	return NewSelector(c)
}

func RegisterCore(t string, f func(c *conf.CoreConfig) (Core, error)) {
	cores[t] = f
}

func RegisteredCore() []string {
	cs := make([]string, 0, len(cores))
	for k := range cores {
		cs = append(cs, k)
	}
	return cs
}
