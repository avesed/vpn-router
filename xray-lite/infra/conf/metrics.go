// Phase XL.4: Metrics module removed
// This file provides stub types for JSON config compatibility
package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"google.golang.org/protobuf/proto"
)

// MetricsConfig is a stub for metrics configuration
type MetricsConfig struct {
	Tag    string `json:"tag"`
	Listen string `json:"listen"`
}

// Build returns nil - metrics module removed
func (c *MetricsConfig) Build() (proto.Message, error) {
	return nil, errors.New("Metrics module removed")
}
