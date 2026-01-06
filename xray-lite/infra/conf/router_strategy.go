// Phase XL.4: Router strategy module removed - Rust rule engine handles routing
// This file provides stub types for JSON config compatibility
package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
	"google.golang.org/protobuf/proto"
)

const (
	strategyRandom     string = "random"
	strategyLeastPing  string = "leastping"
	strategyRoundRobin string = "roundrobin"
	strategyLeastLoad  string = "leastload"
)

var (
	strategyConfigLoader = NewJSONConfigLoader(ConfigCreatorCache{
		strategyRandom:     func() interface{} { return new(strategyEmptyConfig) },
		strategyLeastPing:  func() interface{} { return new(strategyEmptyConfig) },
		strategyRoundRobin: func() interface{} { return new(strategyEmptyConfig) },
		strategyLeastLoad:  func() interface{} { return new(strategyLeastLoadConfig) },
	}, "type", "settings")
)

type strategyEmptyConfig struct {
}

func (v *strategyEmptyConfig) Build() (proto.Message, error) {
	return nil, nil
}

type strategyLeastLoadConfig struct {
	Costs     []interface{}       `json:"costs,omitempty"`
	Baselines []duration.Duration `json:"baselines,omitempty"`
	Expected  int32               `json:"expected,omitempty"`
	MaxRTT    duration.Duration   `json:"maxRTT,omitempty"`
	Tolerance float64             `json:"tolerance,omitempty"`
}

// healthCheckSettings holds settings for health Checker (stub)
type healthCheckSettings struct {
	Destination   string            `json:"destination"`
	Connectivity  string            `json:"connectivity"`
	Interval      duration.Duration `json:"interval"`
	SamplingCount int               `json:"sampling"`
	Timeout       duration.Duration `json:"timeout"`
	HttpMethod    string            `json:"httpMethod"`
}

func (h healthCheckSettings) Build() (proto.Message, error) {
	return nil, errors.New("Health check module removed - use Python health check")
}

// Build implements Buildable (stub).
func (v *strategyLeastLoadConfig) Build() (proto.Message, error) {
	return nil, errors.New("Router strategy module removed - use Rust rule engine")
}
