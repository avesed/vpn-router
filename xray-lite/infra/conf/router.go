// Phase XL.4: Router module removed - Rust rule engine handles routing
// This file provides stub types for JSON config compatibility
package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"google.golang.org/protobuf/proto"
)

// StrategyConfig represents a strategy config stub
type StrategyConfig struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

// BalancingRule is a stub for balancing rule configuration
type BalancingRule struct {
	Tag         string         `json:"tag"`
	Selectors   StringList     `json:"selector"`
	Strategy    StrategyConfig `json:"strategy"`
	FallbackTag string         `json:"fallbackTag"`
}

// Build is a no-op - router module removed
func (r *BalancingRule) Build() (proto.Message, error) {
	return nil, errors.New("Router module removed - use Rust rule engine")
}

// RouterConfig is a stub for router configuration
type RouterConfig struct {
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy *string           `json:"domainStrategy"`
	Balancers      []*BalancingRule  `json:"balancers"`
}

// Build returns nil - router module removed
func (c *RouterConfig) Build() (proto.Message, error) {
	return nil, errors.New("Router module removed - use Rust rule engine")
}

// RouterRule is a stub
type RouterRule struct {
	RuleTag     string `json:"ruleTag"`
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`
}

// ParseRule is a no-op - router module removed
func ParseRule(msg json.RawMessage) (proto.Message, error) {
	return nil, errors.New("Router module removed - use Rust rule engine")
}
