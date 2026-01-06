// Phase XL.4: DNS module removed - sing-box handles DNS
// This file provides stub types for JSON config compatibility
package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"google.golang.org/protobuf/proto"
)

// NameServerConfig is a stub for DNS name server configuration
type NameServerConfig struct {
	Address         *Address   `json:"address"`
	ClientIP        *Address   `json:"clientIp"`
	Port            uint16     `json:"port"`
	SkipFallback    bool       `json:"skipFallback"`
	Domains         []string   `json:"domains"`
	ExpectedIPs     StringList `json:"expectedIPs"`
	ExpectIPs       StringList `json:"expectIPs"`
	QueryStrategy   string     `json:"queryStrategy"`
	Tag             string     `json:"tag"`
	TimeoutMs       uint64     `json:"timeoutMs"`
	DisableCache    *bool      `json:"disableCache"`
	ServeStale      *bool      `json:"serveStale"`
	ServeExpiredTTL *uint32    `json:"serveExpiredTTL"`
	FinalQuery      bool       `json:"finalQuery"`
	UnexpectedIPs   StringList `json:"unexpectedIPs"`
}

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON
func (c *NameServerConfig) UnmarshalJSON(data []byte) error {
	var address Address
	if err := json.Unmarshal(data, &address); err == nil {
		c.Address = &address
		return nil
	}

	var advanced struct {
		Address         *Address   `json:"address"`
		ClientIP        *Address   `json:"clientIp"`
		Port            uint16     `json:"port"`
		SkipFallback    bool       `json:"skipFallback"`
		Domains         []string   `json:"domains"`
		ExpectedIPs     StringList `json:"expectedIPs"`
		ExpectIPs       StringList `json:"expectIPs"`
		QueryStrategy   string     `json:"queryStrategy"`
		Tag             string     `json:"tag"`
		TimeoutMs       uint64     `json:"timeoutMs"`
		DisableCache    *bool      `json:"disableCache"`
		ServeStale      *bool      `json:"serveStale"`
		ServeExpiredTTL *uint32    `json:"serveExpiredTTL"`
		FinalQuery      bool       `json:"finalQuery"`
		UnexpectedIPs   StringList `json:"unexpectedIPs"`
	}
	if err := json.Unmarshal(data, &advanced); err == nil {
		c.Address = advanced.Address
		c.ClientIP = advanced.ClientIP
		c.Port = advanced.Port
		c.SkipFallback = advanced.SkipFallback
		c.Domains = advanced.Domains
		c.ExpectedIPs = advanced.ExpectedIPs
		c.ExpectIPs = advanced.ExpectIPs
		c.QueryStrategy = advanced.QueryStrategy
		c.Tag = advanced.Tag
		c.TimeoutMs = advanced.TimeoutMs
		c.DisableCache = advanced.DisableCache
		c.ServeStale = advanced.ServeStale
		c.ServeExpiredTTL = advanced.ServeExpiredTTL
		c.FinalQuery = advanced.FinalQuery
		c.UnexpectedIPs = advanced.UnexpectedIPs
		return nil
	}

	return errors.New("failed to parse name server: ", string(data))
}

// HostsConfig is a stub
type HostsConfig struct {
	hosts map[string]*HostAddress
}

// HostAddress is a stub
type HostAddress struct {
	addr  *Address
	addrs []*Address
}

// DNSConfig is a stub for DNS configuration
type DNSConfig struct {
	Servers                      []*NameServerConfig `json:"servers"`
	Hosts                        *HostsConfig        `json:"hosts"`
	ClientIP                     *Address            `json:"clientIp"`
	Tag                          string              `json:"tag"`
	QueryStrategy                string              `json:"queryStrategy"`
	CacheStrategy                string              `json:"cacheStrategy"`
	DisableCache                 bool                `json:"disableCache"`
	DisableFallback              bool                `json:"disableFallback"`
	DisableFallbackIfMatch       bool                `json:"disableFallbackIfMatch"`
	ServeStale                   *bool               `json:"serveStale"`
	ServeExpiredTTL              *uint32             `json:"serveExpiredTTL"`
	FailoverTimeoutMs            *uint64             `json:"failoverTimeoutMs"`
	EnableDomainFallbackPriority bool                `json:"enableDomainFallbackPriority"`
}

// Build returns nil - DNS is handled by sing-box
func (c *DNSConfig) Build() (proto.Message, error) {
	return nil, errors.New("DNS module removed - use sing-box for DNS")
}
