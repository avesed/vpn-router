// Phase XL.4: FakeDNS module removed - sing-box handles DNS
// This file provides stub types for JSON config compatibility
package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"google.golang.org/protobuf/proto"
)

// FakeDNSPoolElementConfig is a stub
type FakeDNSPoolElementConfig struct {
	IPPool  string `json:"ipPool"`
	LRUSize int64  `json:"poolSize"`
}

// FakeDNSConfig is a stub for FakeDNS configuration
type FakeDNSConfig struct {
	pool  *FakeDNSPoolElementConfig
	pools []*FakeDNSPoolElementConfig
}

// MarshalJSON implements encoding/json.Marshaler.MarshalJSON
func (f *FakeDNSConfig) MarshalJSON() ([]byte, error) {
	if (f.pool != nil) != (f.pools != nil) {
		if f.pool != nil {
			return json.Marshal(f.pool)
		} else if f.pools != nil {
			return json.Marshal(f.pools)
		}
	}
	return nil, errors.New("unexpected config state")
}

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON
func (f *FakeDNSConfig) UnmarshalJSON(data []byte) error {
	var pool FakeDNSPoolElementConfig
	var pools []*FakeDNSPoolElementConfig
	switch {
	case json.Unmarshal(data, &pool) == nil:
		f.pool = &pool
	case json.Unmarshal(data, &pools) == nil:
		f.pools = pools
	default:
		return errors.New("invalid fakedns config")
	}
	return nil
}

// Build returns nil - FakeDNS is handled by sing-box
func (f *FakeDNSConfig) Build() (proto.Message, error) {
	return nil, errors.New("FakeDNS module removed - use sing-box for DNS")
}

// FakeDNSPostProcessingStage is a no-op stub
type FakeDNSPostProcessingStage struct{}

// Process is a no-op - FakeDNS handled by sing-box
func (FakeDNSPostProcessingStage) Process(config *Config) error {
	return nil
}
