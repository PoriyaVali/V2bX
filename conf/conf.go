package conf

import (
	"fmt"
	"io"
	"os"

	"github.com/PoriyaVali/V2bX/common/json5"

	"encoding/json/v2"
)

type Conf struct {
	LogConfig     LogConfig     `json:"Log"`
	CoresConfig   []CoreConfig  `json:"Cores"`
	NodeConfig    []NodeConfig  `json:"Nodes"`
	MetricsConfig MetricsConfig `json:"Metrics"`
	MemoryConfig  MemoryConfig  `json:"Memory"`
}

// MemoryConfig tunes how V2bX fits into the machine's RAM (see common/memguard).
type MemoryConfig struct {
	// LimitPercent is the share of the RAM ceiling the Go heap aims to stay
	// under. 0 = default (70); negative = no limit. GOMEMLIMIT in the
	// environment overrides it.
	LimitPercent int `json:"LimitPercent"`
}

// MetricsConfig enables the optional Prometheus-text metrics endpoint. Leave
// Listen empty to disable.
type MetricsConfig struct {
	Listen string `json:"Listen"` // e.g. "127.0.0.1:11111"; empty = disabled
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()

	reader := json5.NewTrimNodeReader(f)
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}

	err = json.Unmarshal(data, p)
	if err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}

	return nil
}
