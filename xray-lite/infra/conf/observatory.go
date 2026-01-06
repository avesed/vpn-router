// Phase XL.4: Observatory module removed - Python health check handles this
// This file provides stub types for JSON config compatibility
package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
	"google.golang.org/protobuf/proto"
)

// ObservatoryConfig is a stub for observatory configuration
type ObservatoryConfig struct {
	SubjectSelector   []string          `json:"subjectSelector"`
	ProbeURL          string            `json:"probeURL"`
	ProbeInterval     duration.Duration `json:"probeInterval"`
	EnableConcurrency bool              `json:"enableConcurrency"`
}

// Build returns nil - observatory module removed
func (o *ObservatoryConfig) Build() (proto.Message, error) {
	return nil, errors.New("Observatory module removed - use Python health check")
}

// BurstObservatoryConfig is a stub for burst observatory configuration
type BurstObservatoryConfig struct {
	SubjectSelector []string               `json:"subjectSelector"`
	HealthCheck     *healthCheckSettings   `json:"pingConfig,omitempty"`
}

// Build returns nil - observatory module removed
func (b BurstObservatoryConfig) Build() (proto.Message, error) {
	return nil, errors.New("BurstObservatory module removed - use Python health check")
}
