package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"google.golang.org/protobuf/proto"
)

// GRPCConfig is a stub - gRPC transport has been removed for binary size reduction (Phase XL.3)
type GRPCConfig struct {
	Authority           string `json:"authority"`
	ServiceName         string `json:"serviceName"`
	MultiMode           bool   `json:"multiMode"`
	IdleTimeout         int32  `json:"idle_timeout"`
	HealthCheckTimeout  int32  `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int32  `json:"initial_windows_size"`
	UserAgent           string `json:"user_agent"`
}

// Build implements Buildable - returns error as gRPC has been removed
func (g *GRPCConfig) Build() (proto.Message, error) {
	return nil, errors.New("gRPC transport has been removed for binary size reduction. Use XHTTP instead.")
}
