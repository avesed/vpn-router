package all

import (
	// The following are necessary as they register handlers in their init functions.

	// Mandatory features. Can't remove unless there are replacements.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/xtls/xray-core/app/commander"
	_ "github.com/xtls/xray-core/app/log/command"
	_ "github.com/xtls/xray-core/app/proxyman/command"
	_ "github.com/xtls/xray-core/app/stats/command"

	// REMOVED for binary size reduction (Phase XL.4):
	// _ "github.com/xtls/xray-core/app/observatory/command"  // Python health check handles this

	// Other optional features.
	// REMOVED for binary size reduction (Phase XL.4):
	// _ "github.com/xtls/xray-core/app/dns"          // sing-box handles DNS
	// _ "github.com/xtls/xray-core/app/dns/fakedns"  // sing-box handles DNS
	_ "github.com/xtls/xray-core/app/log"
	// _ "github.com/xtls/xray-core/app/metrics"      // Not needed
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/reverse"
	// _ "github.com/xtls/xray-core/app/router"       // Rust rule engine handles routing
	_ "github.com/xtls/xray-core/app/stats"

	// Fix dependency cycle caused by core import in internet package
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"

	// REMOVED for binary size reduction (Phase XL.4):
	// _ "github.com/xtls/xray-core/app/observatory"  // Python health check handles this

	// Inbound and outbound proxies.
	// KEPT: vless (primary protocol), freedom (direct), socks (bridge), dokodemo (stats API)
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"

	// REMOVED for binary size reduction (Phase XL.2):
	// _ "github.com/xtls/xray-core/proxy/blackhole"    // Not needed
	// _ "github.com/xtls/xray-core/proxy/dns"          // sing-box handles DNS
	// _ "github.com/xtls/xray-core/proxy/http"         // Not needed
	// _ "github.com/xtls/xray-core/proxy/loopback"     // Not needed
	// _ "github.com/xtls/xray-core/proxy/shadowsocks"  // Not needed
	// _ "github.com/xtls/xray-core/proxy/trojan"       // Not needed
	// _ "github.com/xtls/xray-core/proxy/vmess/inbound"  // Not needed
	// _ "github.com/xtls/xray-core/proxy/vmess/outbound" // Not needed
	// _ "github.com/xtls/xray-core/proxy/wireguard"    // Kernel WG used instead (big: gvisor dependency)

	// Transports
	// KEPT: reality, splithttp (XHTTP), tcp, tls, udp - core transports needed for VLESS
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"

	// REMOVED for binary size reduction (Phase XL.3):
	// _ "github.com/xtls/xray-core/transport/internet/grpc"       // Use XHTTP instead
	// _ "github.com/xtls/xray-core/transport/internet/httpupgrade" // Use XHTTP instead
	// _ "github.com/xtls/xray-core/transport/internet/kcp"        // Legacy, not needed
	// _ "github.com/xtls/xray-core/transport/internet/websocket"  // Use XHTTP instead

	// Transport headers
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/headers/srtp"
	_ "github.com/xtls/xray-core/transport/internet/headers/tls"
	_ "github.com/xtls/xray-core/transport/internet/headers/utp"
	_ "github.com/xtls/xray-core/transport/internet/headers/wechat"
	_ "github.com/xtls/xray-core/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/xtls/xray-core/main/json"
	_ "github.com/xtls/xray-core/main/toml"
	_ "github.com/xtls/xray-core/main/yaml"

	// Load config from file or http(s)
	_ "github.com/xtls/xray-core/main/confloader/external"

	// Commands
	_ "github.com/xtls/xray-core/main/commands/all"
)
