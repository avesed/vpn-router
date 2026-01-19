export interface WireGuardPeer {
  address: string;
  port: number;
  public_key: string;
  pre_shared_key?: string;
  allowed_ips?: string[];
  persistent_keepalive_interval?: number;
  reserved?: number[];
}

export interface Endpoint {
  type: string;
  tag: string;
  address?: string[];
  private_key?: string;
  mtu?: number;
  workers?: number;
  peers?: WireGuardPeer[];
}

export interface RustRouterStatus {
  running: boolean;
  version?: string;
  uptime_secs?: number;
  active_connections?: number;
  total_connections?: number;
  accepting?: boolean;
}

export interface GatewayStatus {
  timestamp: string;
  sing_box_running: boolean;
  rust_router_running: boolean;
  rust_router?: RustRouterStatus;
  wireguard_interface: Record<string, unknown>;
  config_mtime?: number;
  pia_profiles?: PiaProfile[];
}

export interface PiaProfile {
  name: string;
  description: string;
  region_id: string;
  custom_dns: string;  // 自定义 DNS，空=使用 PIA DNS
}

export interface ProfileStatus {
  tag: string;
  description: string;
  region_id: string;
  server_ip: string;
  server_port: number;
  is_configured: boolean;
  status: "connected" | "disconnected";
}

export interface ProfilesStatusResponse {
  profiles: ProfileStatus[];
  sing_box_running: boolean;
}

export interface PiaLoginResponse {
  message: string;
  reload?: {
    success: boolean;
    message: string;
    method?: string;
  };
}

// PIA Regions
export interface PiaRegion {
  id: string;
  name: string;
  country: string;
  port_forward: boolean;
  geo: boolean;
}

export interface PiaRegionsResponse {
  regions: PiaRegion[];
}

// Profile Management
export interface VpnProfile {
  tag: string;
  name: string;
  description: string;
  region_id: string;
  custom_dns: string;  // 自定义 DNS，空=使用 PIA DNS
  server_ip?: string;
  server_port?: number;
  is_connected: boolean;
}

export interface ProfilesResponse {
  profiles: VpnProfile[];
}

// Route Rules
export interface RouteRule {
  tag: string;
  outbound: string;
  domains?: string[];
  domain_keywords?: string[];
  ip_cidrs?: string[];
  // 协议/端口匹配字段 (sing-box 流量类型嗅探)
  protocols?: string[];      // bittorrent, stun, ssh, rdp, etc.
  network?: string;          // tcp, udp
  ports?: number[];          // 单个端口 [80, 443]
  port_ranges?: string[];    // 端口范围 ["6881:6889", "51413"]
  type?: "custom" | "geosite" | "geoip" | "protocol";
}

// sing-box protocol sniffing options
export const PROTOCOL_OPTIONS = [
  { value: "bittorrent", label: "BitTorrent", description: "Torrent traffic" },
  { value: "stun", label: "STUN", description: "VoIP/WebRTC traffic" },
  { value: "dtls", label: "DTLS", description: "Secure UDP traffic" },
  { value: "ssh", label: "SSH", description: "SSH connections" },
  { value: "rdp", label: "RDP", description: "Remote Desktop" },
  { value: "dns", label: "DNS", description: "DNS queries" },
  { value: "ntp", label: "NTP", description: "Time sync" },
  { value: "http", label: "HTTP", description: "HTTP traffic" },
  { value: "tls", label: "TLS", description: "HTTPS/SSL traffic" },
  { value: "quic", label: "QUIC", description: "HTTP/3 traffic" },
] as const;

// Network type options
export const NETWORK_OPTIONS = [
  { value: "", label: "Any", description: "Match all network types" },
  { value: "tcp", label: "TCP", description: "TCP traffic only" },
  { value: "udp", label: "UDP", description: "UDP traffic only" },
] as const;

export interface RouteRulesResponse {
  rules: RouteRule[];
  custom_rules: RouteRule[];
  default_outbound: string;
  available_outbounds: string[];
}

// Domain Catalog
export interface DomainListSummary {
  id: string;
  domain_count: number;
  sample_domains: string[];
  is_custom?: boolean;
}

export interface TypeBreakdownItem {
  name: string;
  count: number;
  lists: string[];
}

export interface DomainCategory {
  name: string;
  description: string;
  group?: "type" | "region";  // Optional, legacy field
  recommended_exit: string;
  lists: DomainListSummary[];
  type_breakdown?: Record<string, TypeBreakdownItem>;
}

export interface DomainCatalogResponse {
  categories: Record<string, DomainCategory>;
}

export interface DomainCategorySummary {
  id: string;
  name: string;
  description: string;
  recommended_exit: string;
  list_count: number;
}

export interface DomainCategoriesResponse {
  categories: DomainCategorySummary[];
}

export interface DomainListResponse {
  id: string;
  domains: string[];
  full_domains: string[];
}

export interface DomainSearchResult {
  id: string;
  name: string;
}

export interface DomainSearchResponse {
  results: DomainSearchResult[];
}

export interface QuickRuleResponse {
  message: string;
  tag: string;
  domain_count: number;
  outbound: string;
}

// IP Catalog
export interface CountryIpInfo {
  country_code: string;
  country_name: string;
  display_name: string;
  ipv4_count: number;
  ipv6_count: number;
  recommended_exit: string;
  sample_ipv4?: string[];
  ipv4_cidrs?: string[];
  ipv6_cidrs?: string[];
}

export interface IpCatalogResponse {
  countries: Record<string, CountryIpInfo>;
  stats: {
    total_countries: number;
    total_ipv4_cidrs?: number;
    total_ipv6_cidrs?: number;
  };
}

export interface CountrySearchResult {
  country_code: string;
  display_name: string;
}

export interface IpSearchResponse {
  results: CountrySearchResult[];
}

export interface IpQuickRuleResponse {
  message: string;
  tag: string;
  cidr_count: number;
  outbound: string;
}

// Ingress WireGuard
export interface IngressInterface {
  name: string;
  address: string;
  listen_port: number;
  mtu: number;
  public_key: string;
}

export interface IngressPeer {
  name: string;
  public_key: string;
  allowed_ips: string[];
  last_handshake: number;
  is_online: boolean;
  rx_bytes: number;
  tx_bytes: number;
  default_outbound?: string | null;
}

export interface IngressResponse {
  interface: IngressInterface;
  peers: IngressPeer[];
  peer_count: number;
  local_node_tag?: string;
}

export interface IngressPeerCreateResponse {
  message: string;
  peer: {
    name: string;
    public_key: string;
    address: string;
  };
  client_private_key?: string;
  apply_result: {
    success: boolean;
    message: string;
  };
}

// Subnet Configuration
export interface SubnetConflict {
  type: string;      // "custom_egress" | "pia_profile"
  tag: string;       // egress tag/name
  address: string;   // conflicting IP address
}

export interface SubnetInfo {
  address: string;
  conflicts: SubnetConflict[];
}

export interface SubnetUpdateRequest {
  address: string;
  migrate_peers: boolean;
}

export interface SubnetUpdateResponse {
  message: string;
  address: string;
  migrated_peers?: number;
  reload_status?: {
    success: boolean;
    message: string;
  };
}

// Custom Egress
export interface CustomEgress {
  tag: string;
  description: string;
  server: string;
  port: number;
  private_key: string;
  public_key: string;
  address: string;
  mtu: number;
  dns: string;
  pre_shared_key?: string;
  reserved?: number[];
}

export interface CustomEgressCreateRequest {
  tag: string;
  description?: string;
  server: string;
  port?: number;
  private_key: string;
  public_key: string;
  address: string;
  mtu?: number;
  dns?: string;
  pre_shared_key?: string;
  reserved?: number[];
}

export interface EgressItem {
  tag: string;
  description: string;
  type: "pia" | "custom" | "direct" | "openvpn" | "v2ray" | "warp";
  server?: string;
  port?: number;
  is_configured: boolean;
  // Direct egress specific fields
  bind_interface?: string;
  inet4_bind_address?: string;
  inet6_bind_address?: string;
  enabled?: number;
  // OpenVPN specific fields
  protocol?: string;
  tun_device?: string;
  status?: "connected" | "connecting" | "disconnected" | "error";
  // V2Ray specific fields
  transport?: string;
  tls_enabled?: number;
}

export interface AllEgressResponse {
  pia: EgressItem[];
  custom: EgressItem[];
  direct: EgressItem[];
  openvpn: EgressItem[];
  v2ray: EgressItem[];
  warp?: EgressItem[];
}

// Traffic stats for WireGuard tunnels
export interface EgressTrafficInfo {
  tx_bytes: number;
  rx_bytes: number;
  active: boolean;
  endpoint: string;
  last_handshake: number;
}

export interface EgressTrafficResponse {
  traffic: Record<string, EgressTrafficInfo>;
}

// Direct Egress (绑定特定接口/IP 的直连出口)
export interface DirectEgress {
  id?: number;
  tag: string;
  description: string;
  bind_interface?: string;
  inet4_bind_address?: string;
  inet6_bind_address?: string;
  enabled: number;
  created_at?: string;
  updated_at?: string;
}

export interface DirectEgressCreateRequest {
  tag: string;
  description?: string;
  bind_interface?: string;
  inet4_bind_address?: string;
  inet6_bind_address?: string;
}

export interface DirectEgressUpdateRequest {
  description?: string;
  bind_interface?: string;
  inet4_bind_address?: string;
  inet6_bind_address?: string;
  enabled?: number;
}

export interface DirectEgressListResponse {
  egress: DirectEgress[];
}

// OpenVPN Egress (通过 direct + bind_interface 直接绑定 TUN 接口)
export interface OpenVPNEgress {
  id?: number;
  tag: string;
  description: string;
  protocol: "udp" | "tcp";
  remote_host: string;
  remote_port: number;
  ca_cert: string;
  client_cert?: string;
  client_key?: string;
  tls_auth?: string;
  tls_crypt?: string;
  crl_verify?: string;
  auth_user?: string;
  auth_pass?: string;
  cipher: string;
  auth: string;
  compress?: string;
  extra_options?: string;
  tun_device?: string;
  enabled: number;
  created_at?: string;
  updated_at?: string;
}

export interface OpenVPNEgressCreateRequest {
  tag: string;
  description?: string;
  protocol?: "udp" | "tcp";
  remote_host: string;
  remote_port?: number;
  ca_cert: string;
  client_cert?: string;
  client_key?: string;
  tls_auth?: string;
  tls_crypt?: string;
  crl_verify?: string;
  auth_user?: string;
  auth_pass?: string;
  cipher?: string;
  auth?: string;
  compress?: string;
  extra_options?: string;
}

export interface OpenVPNEgressUpdateRequest {
  description?: string;
  protocol?: "udp" | "tcp";
  remote_host?: string;
  remote_port?: number;
  ca_cert?: string;
  client_cert?: string;
  client_key?: string;
  tls_auth?: string;
  tls_crypt?: string;
  crl_verify?: string;
  auth_user?: string;
  auth_pass?: string;
  cipher?: string;
  auth?: string;
  compress?: string;
  extra_options?: string;
  enabled?: number;
}

export interface OpenVPNEgressListResponse {
  egress: OpenVPNEgress[];
}

export interface OpenVPNParseResult {
  protocol?: string;
  remote_host?: string;
  remote_port?: number;
  ca_cert?: string;
  client_cert?: string;
  client_key?: string;
  tls_auth?: string;
  tls_crypt?: string;
  crl_verify?: string;
  auth_user?: string;
  auth_pass?: string;
  cipher?: string;
  auth?: string;
  compress?: string;
  requires_auth?: boolean;
}

export interface OpenVPNTunnelStatus {
  tag: string;
  status: "connected" | "connecting" | "disconnected" | "error";
  message?: string;
  tun_device?: string;
  openvpn_pid?: number;
}

export interface CustomEgressListResponse {
  egress: CustomEgress[];
}

export interface WireGuardConfParseResult {
  private_key: string;
  address: string;
  dns?: string;
  mtu?: number;
  server: string;
  port: number;
  public_key: string;
  pre_shared_key?: string;
}

// Backup / Restore (v2.0: SQLCipher 加密数据库)
export interface BackupStatus {
  // v2.0 新增字段
  backup_version: string;
  database_size_bytes: number;
  database_encrypted: boolean;
  key_manager_available: boolean;
  // 兼容字段
  encryption_available: boolean;
  has_ingress: boolean;
  ingress_peer_count: number;
  custom_egress_count: number;
  pia_profile_count: number;
  has_pia_credentials: boolean;
  has_settings: boolean;
}

export interface BackupExportRequest {
  password: string;  // v2.0: 密码必需
}

export interface BackupExportResponse {
  message: string;
  backup: {
    version: string;
    type: string;
    created_at: string;
    checksum: string;
    database_size_bytes: number;
    database: string;  // base64 编码的加密数据库
    encryption_key: {
      salt: string;
      data: string;
    };
  };
}

export interface BackupImportRequest {
  data: string;
  password: string;  // v2.0: 密码必需
}

export interface BackupImportResponse {
  message: string;
  checksum_verified?: boolean;
  results: {
    database_replaced: boolean;
    key_replaced: boolean;
  };
}

// AdBlock Rule Sets
export interface AdBlockRuleSet {
  tag: string;
  name: string;
  description: string;
  url: string;
  format: "adblock" | "hosts" | "domains";
  outbound: string;
  enabled: number;
  priority: number;
  category: string;
  region?: string;
}

export interface AdBlockRulesResponse {
  rules: AdBlockRuleSet[];
  by_category: Record<string, AdBlockRuleSet[]>;
  total: number;
  enabled_count: number;
}

export interface AdBlockRuleSetCreateRequest {
  tag: string;
  name: string;
  url: string;
  description?: string;
  format?: string;
  outbound?: string;
  category?: string;
  region?: string;
  priority?: number;
}

export interface AdBlockToggleResponse {
  message: string;
  tag: string;
  enabled: boolean;
}

// Dashboard Stats
export interface RateHistoryPoint {
  timestamp: number;
  rates: Record<string, number>;  // {outbound: rate_kb}
}

export interface DashboardStats {
  online_clients: number;
  total_clients: number;
  traffic_by_outbound: Record<string, { download: number; upload: number }>;
  traffic_rates: Record<string, { download_rate: number; upload_rate: number }>;
  rate_history: RateHistoryPoint[];  // 24小时速率历史
  adblock_connections: number;
  active_connections: number;
}

// Egress Connection Test
export interface EgressTestResponse {
  success: boolean;
  delay: number;
  message: string;
}

// Egress Speed Test
export interface SpeedTestResponse {
  success: boolean;
  speed_mbps: number;
  download_bytes?: number;
  duration_sec?: number;
  message: string;
}

// ============ V2Ray Egress Types ============
// [Phase XL] Only VLESS is supported for new configs
// VMess/Trojan kept in type for backwards compat (reading existing data)

export type V2RayProtocol = "vmess" | "vless" | "trojan";
export type V2RayProtocolSupported = "vless"; // Only VLESS supported in xray-lite
export type V2RayTransport = "tcp" | "ws" | "grpc" | "h2" | "quic" | "httpupgrade" | "xhttp";

export interface V2RayTransportConfig {
  path?: string;
  host?: string;
  service_name?: string;
  headers?: Record<string, string>;
  early_data_header_name?: string;
  max_early_data?: number;
  // XHTTP specific
  mode?: "auto" | "packet-up" | "stream-up" | "stream-one";
}

export interface V2RayEgress {
  id?: number;
  tag: string;
  description: string;
  protocol: V2RayProtocol;
  server: string;
  server_port: number;
  // Auth
  uuid?: string;
  password?: string;
  // VMess specific
  security?: string;
  alter_id?: number;
  // VLESS specific
  flow?: string;
  // TLS
  tls_enabled: number;
  tls_sni?: string;
  tls_alpn?: string;  // JSON array string
  tls_allow_insecure: number;
  tls_fingerprint?: string;
  // REALITY (VLESS)
  reality_enabled: number;
  reality_public_key?: string;
  reality_short_id?: string;
  // Transport
  transport_type: V2RayTransport;
  transport_config?: string;  // JSON string
  // Multiplex
  multiplex_enabled: number;
  multiplex_protocol?: string;
  multiplex_max_connections?: number;
  multiplex_min_streams?: number;
  multiplex_max_streams?: number;
  // Other
  enabled: number;
  created_at?: string;
  updated_at?: string;
}

export interface V2RayEgressCreateRequest {
  tag: string;
  description?: string;
  protocol: V2RayProtocol;
  server: string;
  server_port?: number;
  uuid?: string;
  password?: string;
  security?: string;
  alter_id?: number;
  flow?: string;
  tls_enabled?: boolean;
  tls_sni?: string;
  tls_alpn?: string[];
  tls_allow_insecure?: boolean;
  tls_fingerprint?: string;
  reality_enabled?: boolean;
  reality_public_key?: string;
  reality_short_id?: string;
  transport_type?: V2RayTransport;
  transport_config?: V2RayTransportConfig;
  multiplex_enabled?: boolean;
  multiplex_protocol?: string;
  multiplex_max_connections?: number;
  multiplex_min_streams?: number;
  multiplex_max_streams?: number;
}

export interface V2RayEgressUpdateRequest {
  description?: string;
  protocol?: V2RayProtocol;
  server?: string;
  server_port?: number;
  uuid?: string;
  password?: string;
  security?: string;
  alter_id?: number;
  flow?: string;
  tls_enabled?: boolean;
  tls_sni?: string;
  tls_alpn?: string[];
  tls_allow_insecure?: boolean;
  tls_fingerprint?: string;
  reality_enabled?: boolean;
  reality_public_key?: string;
  reality_short_id?: string;
  transport_type?: V2RayTransport;
  transport_config?: V2RayTransportConfig;
  multiplex_enabled?: boolean;
  multiplex_protocol?: string;
  multiplex_max_connections?: number;
  multiplex_min_streams?: number;
  multiplex_max_streams?: number;
  enabled?: number;
}

export interface V2RayEgressListResponse {
  egress: V2RayEgress[];
}

export interface V2RayURIParseResult {
  protocol: V2RayProtocol;
  remark?: string;
  description?: string;
  server: string;
  server_port: number;
  uuid?: string;
  password?: string;
  security?: string;
  alter_id?: number;
  flow?: string;
  tls_enabled?: boolean;
  tls_sni?: string;
  tls_alpn?: string[];
  tls_fingerprint?: string;
  tls_allow_insecure?: boolean;
  reality_enabled?: boolean;
  reality_public_key?: string;
  reality_short_id?: string;
  transport_type?: V2RayTransport;
  transport_config?: V2RayTransportConfig;
}

// ============ V2Ray Inbound Types ============

export interface V2RayInboundConfig {
  id?: number;
  protocol: V2RayProtocol;
  listen_address: string;
  listen_port: number;
  tls_enabled: number;
  tls_cert_path?: string;
  tls_key_path?: string;
  tls_cert_content?: string;
  tls_key_content?: string;
  transport_type: V2RayTransport;
  transport_config?: string;  // JSON string
  fallback_server?: string;
  fallback_port?: number;
  // Xray/REALITY specific fields
  xtls_vision_enabled: number;
  reality_enabled: number;
  reality_private_key?: string;
  reality_public_key?: string;
  reality_short_ids?: string[];  // Parsed from JSON
  reality_dest?: string;
  reality_server_names?: string[];  // Parsed from JSON
  tun_device?: string;
  tun_subnet?: string;
  enabled: number;
  created_at?: string;
  updated_at?: string;
}

export interface V2RayInboundUpdateRequest {
  protocol?: V2RayProtocol;
  listen_address?: string;
  listen_port?: number;
  tls_enabled?: boolean;
  tls_cert_path?: string;
  tls_key_path?: string;
  tls_cert_content?: string;
  tls_key_content?: string;
  transport_type?: V2RayTransport;
  transport_config?: V2RayTransportConfig;
  fallback_server?: string;
  fallback_port?: number;
  // Xray/REALITY specific fields
  xtls_vision_enabled?: boolean;
  reality_enabled?: boolean;
  reality_private_key?: string;
  reality_public_key?: string;
  reality_short_ids?: string[];
  reality_dest?: string;
  reality_server_names?: string[];
  tun_device?: string;
  tun_subnet?: string;
  enabled?: boolean;
}

export interface V2RayUser {
  id: number;
  name: string;
  email?: string;
  uuid?: string;
  password?: string;
  alter_id?: number;
  flow?: string;
  enabled: number;
  created_at?: string;
  updated_at?: string;
}

export interface V2RayUserCreateRequest {
  name: string;
  email?: string;
  uuid?: string;
  password?: string;
  alter_id?: number;
  flow?: string;
}

export interface V2RayUserUpdateRequest {
  email?: string;
  uuid?: string;
  password?: string;
  alter_id?: number;
  flow?: string;
  enabled?: number;
}

export interface V2RayInboundResponse {
  config: V2RayInboundConfig;
  users: V2RayUser[];
}

export interface V2RayUserShareResponse {
  uri: string;
  protocol: V2RayProtocol;
  user: string;
}

// Xray status and control types
export interface XrayStatus {
  running: boolean;
  enabled: boolean;
  pid?: number;
  uptime?: number;
  tun_device?: string;
  tun_configured: boolean;
  reality_enabled: boolean;
  xtls_vision_enabled: boolean;
  listen_port?: number;
  message?: string;
}

export interface RealityKeyPair {
  private_key: string;
  public_key: string;
}

// V2Ray protocol options for UI
// [Phase XL] Only VLESS is supported - VMess/Trojan removed from xray-lite
export const V2RAY_PROTOCOLS = [
  { value: "vless", label: "VLESS", description: "VLESS protocol with REALITY/XTLS-Vision" },
] as const;

// Legacy protocol type for displaying existing configs (read-only)
export type V2RayProtocolLegacy = "vmess" | "vless" | "trojan";

export const V2RAY_TRANSPORTS = [
  { value: "tcp", label: "TCP", description: "Raw TCP" },
  { value: "ws", label: "WebSocket", description: "WebSocket transport" },
  { value: "grpc", label: "gRPC", description: "gRPC transport" },
  { value: "h2", label: "HTTP/2", description: "HTTP/2 transport" },
  { value: "quic", label: "QUIC", description: "QUIC transport" },
  { value: "httpupgrade", label: "HTTPUpgrade", description: "HTTP upgrade" },
  { value: "xhttp", label: "XHTTP", description: "XHTTP transport (Xray)" },
] as const;

export const V2RAY_SECURITY_OPTIONS = [
  { value: "auto", label: "Auto", description: "Auto select" },
  { value: "aes-128-gcm", label: "AES-128-GCM", description: "AES-128-GCM" },
  { value: "chacha20-poly1305", label: "ChaCha20-Poly1305", description: "ChaCha20-Poly1305" },
  { value: "none", label: "None", description: "No encryption" },
  { value: "zero", label: "Zero", description: "Zero encryption" },
] as const;

export const V2RAY_TLS_FINGERPRINTS = [
  { value: "", label: "Default", description: "Default" },
  { value: "chrome", label: "Chrome", description: "Chrome browser" },
  { value: "firefox", label: "Firefox", description: "Firefox browser" },
  { value: "safari", label: "Safari", description: "Safari browser" },
  { value: "edge", label: "Edge", description: "Edge browser" },
  { value: "ios", label: "iOS", description: "iOS system" },
  { value: "android", label: "Android", description: "Android system" },
  { value: "random", label: "Random", description: "Random" },
  { value: "randomized", label: "Randomized", description: "Fully randomized" },
] as const;

export const V2RAY_MULTIPLEX_PROTOCOLS = [
  { value: "smux", label: "smux", description: "smux protocol" },
  { value: "yamux", label: "yamux", description: "yamux protocol" },
  { value: "h2mux", label: "h2mux", description: "HTTP/2 multiplexing" },
] as const;

export const VLESS_FLOW_OPTIONS = [
  { value: "", label: "None", description: "No flow control" },
  { value: "xtls-rprx-vision", label: "xtls-rprx-vision", description: "XTLS Vision flow control" },
] as const;

// ============ WARP Egress 类型 ============

export type WarpAccountType = "free" | "warp+" | "teams";
export type WarpMode = "socks" | "tun";
export type WarpProtocol = "masque" | "wireguard";

export interface WarpEgress {
  id?: number;
  tag: string;
  description: string;
  config_path?: string;
  license_key?: string;
  account_type: WarpAccountType;
  protocol: WarpProtocol;
  mode: WarpMode;
  socks_port?: number;
  endpoint_v4?: string;
  endpoint_v6?: string;
  enabled: number;
  created_at?: string;
  updated_at?: string;
}

export interface WarpEgressRegisterRequest {
  tag: string;
  description?: string;
  license_key?: string;
  protocol?: WarpProtocol;
}

export interface WarpEgressUpdateRequest {
  description?: string;
  enabled?: number;
}

export interface WarpEgressEndpointRequest {
  endpoint_v4?: string;
  endpoint_v6?: string;
}

export interface WarpEgressLicenseRequest {
  license_key: string;
}

export interface WarpEgressListResponse {
  warp_egress: WarpEgress[];
}

export interface WarpEgressStatus {
  tag: string;
  running: boolean;
  pid?: number;
  mode?: string;
  uptime?: number;
  error?: string;
}

export interface WarpEndpointResult {
  ip: string;
  port: number;
  endpoint: string;
  loss_rate: number;
  latency_ms: number;
  min_latency_ms: number;
  max_latency_ms: number;
  success_count: number;
  test_count: number;
}

export interface WarpEndpointTestRequest {
  endpoints?: string[];
  sample_count?: number;
  top_n?: number;
}

export interface WarpEndpointTestResponse {
  results: WarpEndpointResult[];
  message?: string;
}

export const WARP_ACCOUNT_TYPES = [
  { value: "free", label: "Free", description: "免费版 WARP" },
  { value: "warp+", label: "WARP+", description: "付费版 WARP，更快的速度" },
  { value: "teams", label: "Teams", description: "企业版 WARP" },
] as const;

// ============ Outbound Groups 类型 (ECMP 负载均衡) ============

export type OutboundGroupType = "loadbalance" | "failover";

export type EcmpAlgorithm = 
  | "five_tuple_hash" 
  | "dest_hash" 
  | "dest_hash_least_load"
  | "round_robin" 
  | "weighted" 
  | "least_connections" 
  | "random";

export interface OutboundGroup {
  id: number;
  tag: string;
  description: string;
  type: OutboundGroupType;
  members: string[];  // 解析后的数组
  weights?: Record<string, number>;  // 解析后的对象
  algorithm?: EcmpAlgorithm;  // ECMP 算法
  health_check_url: string;
  health_check_interval: number;
  health_check_timeout: number;
  routing_table: number;
  enabled: number;
  health_status?: Record<string, MemberHealthStatus>;  // 各成员健康状态
  created_at?: string;
  updated_at?: string;
}

export interface MemberHealthStatus {
  healthy: boolean;
  latency_ms: number;
  last_check: string;
  error?: string;
}

export interface OutboundGroupCreateRequest {
  tag: string;
  description?: string;
  type: OutboundGroupType;
  members: string[];
  weights?: Record<string, number>;
  algorithm?: EcmpAlgorithm;
  health_check_url?: string;
  health_check_interval?: number;
  health_check_timeout?: number;
}

export interface OutboundGroupUpdateRequest {
  description?: string;
  members?: string[];
  weights?: Record<string, number>;
  algorithm?: EcmpAlgorithm;
  health_check_url?: string;
  health_check_interval?: number;
  health_check_timeout?: number;
  enabled?: boolean;
}

export interface OutboundGroupListResponse {
  groups: OutboundGroup[];
}

export interface AvailableMember {
  tag: string;
  type: string;  // 'pia', 'wireguard', 'direct', 'openvpn', 'v2ray', 'warp', 'builtin'
  description: string;
}

export interface AvailableMembersResponse {
  members: AvailableMember[];
}

export interface GroupHealthCheckResponse {
  success: boolean;
  tag: string;
  health_status: Record<string, MemberHealthStatus>;
}

export const OUTBOUND_GROUP_TYPES = [
  { value: "loadbalance", label: "Load Balance", description: "流量均匀分散到所有成员" },
  { value: "failover", label: "Failover", description: "优先使用第一个健康的成员" },
] as const;

export const ECMP_ALGORITHMS = [
  { value: "five_tuple_hash", label: "Five Tuple Hash", description: "基于源IP、目标IP、源端口、目标端口、协议的哈希（默认）" },
  { value: "dest_hash", label: "Dest Hash", description: "基于源IP+域名的哈希，同一客户端访问同一域名始终使用相同出口（视频流优化）" },
  { value: "dest_hash_least_load", label: "Dest Hash + Least Load", description: "智能调度：新会话选择负载最低出口，已有会话保持亲和性（推荐用于视频）" },
  { value: "round_robin", label: "Round Robin", description: "轮询，依次使用每个成员" },
  { value: "weighted", label: "Weighted", description: "按权重比例分配流量" },
  { value: "least_connections", label: "Least Connections", description: "选择当前连接数最少的成员" },
  { value: "random", label: "Random", description: "随机选择成员" },
] as const;

// ============ Peer Nodes 类型 (对等节点) ============

export type PeerTunnelType = "wireguard" | "xray";
export type PeerTunnelStatus = "disconnected" | "connecting" | "connected" | "error";

// XHTTP mode options for VLESS+XHTTP+REALITY
export type XHttpMode = "auto" | "packet-up" | "stream-up" | "stream-one";

export interface PeerNode {
  inbound_enabled?: number;
  inbound_port?: number;
  inbound_uuid?: string;
  inbound_socks_port?: number;
  xray_inbound_process_status?: string;

  id?: number;
  tag: string;
  name: string;
  description?: string;
  endpoint: string;
  api_port?: number;  // Phase D: API 端口 (默认 36000)
  tunnel_type: PeerTunnelType;
  tunnel_status: PeerTunnelStatus;
  tunnel_interface?: string;
  tunnel_local_ip?: string;
  tunnel_remote_ip?: string;
  tunnel_port?: number;
  xray_socks_port?: number;

  // REALITY 配置（本节点作为服务端）- 自动生成，只读
  xray_reality_private_key?: string;
  xray_reality_public_key?: string;
  xray_reality_short_id?: string;
  xray_reality_dest?: string;  // 默认: www.microsoft.com:443
  xray_reality_server_names?: string;  // JSON 数组，如 ["www.microsoft.com"]

  // 对端 REALITY 配置（本节点作为客户端连接对端时使用）- 从交换获得
  xray_peer_reality_public_key?: string;
  xray_peer_reality_short_id?: string;
  xray_peer_reality_dest?: string;
  xray_peer_reality_server_names?: string;  // JSON 数组

  // XHTTP 传输配置
  xray_xhttp_path?: string;  // 默认: /
  xray_xhttp_mode?: XHttpMode;  // 默认: auto
  xray_xhttp_host?: string;

  last_seen?: string;
  last_error?: string;
  auto_reconnect: boolean;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;

  // 双向连接状态 (Phase 11.2)
  bidirectional_status?: "pending" | "outbound_only" | "bidirectional";
}

export interface PeerNodeCreateRequest {
  tag: string;
  name: string;
  description?: string;
  endpoint: string;
  // NOTE: psk field removed - WireGuard uses tunnel IP authentication, Xray uses UUID authentication
  tunnel_type: PeerTunnelType;

  // REALITY 服务端配置（可选，有默认值）
  xray_reality_dest?: string;  // 默认: www.microsoft.com:443
  xray_reality_server_names?: string[];  // 默认: ["www.microsoft.com"]

  // XHTTP 传输配置（可选，有默认值）
  xray_xhttp_path?: string;  // 默认: /
  xray_xhttp_mode?: XHttpMode;  // 默认: auto
  xray_xhttp_host?: string;

  auto_reconnect?: boolean;
}

export interface PeerNodeUpdateRequest {
  name?: string;
  description?: string;
  endpoint?: string;
  // NOTE: psk field removed - WireGuard uses tunnel IP authentication, Xray uses UUID authentication

  // REALITY 服务端配置
  xray_reality_dest?: string;
  xray_reality_server_names?: string[];

  // XHTTP 传输配置
  xray_xhttp_path?: string;
  xray_xhttp_mode?: XHttpMode;
  xray_xhttp_host?: string;

  auto_reconnect?: boolean;
  enabled?: boolean;
}

export interface PeerNodeListResponse {
  nodes: PeerNode[];
}

export interface PeerNodeStatusResponse {
  tag: string;
  tunnel_status: PeerTunnelStatus;
  tunnel_interface?: string;
  tunnel_local_ip?: string;
  tunnel_remote_ip?: string;
  last_seen?: string;
  last_error?: string;
}

export interface PeerNodeConnectResponse {
  success: boolean;
  message: string;
  tag: string;
  tunnel_status: PeerTunnelStatus;
  tunnel_interface?: string;
  remote_notified?: boolean;  // 是否成功通知远程节点
}

export interface PeerNodeDisconnectResponse {
  success: boolean;
  message: string;
  tag: string;
  remote_notified?: boolean;  // 是否成功通知远程节点
}

export interface BatchOperationRequest {
  tags: string[];
}

export interface BatchOperationResponse {
  success: boolean;
  results: Record<string, { success: boolean; message: string }>;
}

// ============ Node Chains Types (Multi-hop Chains) ============

export type ChainHealthStatus = "unknown" | "healthy" | "degraded" | "unhealthy";

// Downstream status for cascade notifications
export type DownstreamStatus = "unknown" | "connected" | "disconnected";

// Chain activation state
export type ChainState = "inactive" | "activating" | "active" | "error";

// Chain mark type for multi-hop routing
export type ChainMarkType = "dscp" | "xray_email";

export interface NodeChain {
  id?: number;
  tag: string;
  name: string;
  description?: string;
  hops: string[];  // Array of node tags in order
  hop_protocols?: Record<string, string>;  // {node_tag: protocol}
  entry_rules?: Record<string, unknown>;
  relay_rules?: Record<string, unknown>;
  health_status: ChainHealthStatus;
  downstream_status?: DownstreamStatus;  // Status of downstream nodes (cascade notification)
  disconnected_node?: string;  // The disconnected downstream node tag (if any)
  last_health_check?: string;
  enabled: boolean;
  priority: number;
  // Multi-hop chain architecture v2 fields
  exit_egress?: string;  // Terminal node's local egress
  dscp_value?: number;  // DSCP marking value (1-63)
  chain_mark_type?: ChainMarkType;  // "dscp" or "xray_email"
  chain_state?: ChainState;  // "inactive", "activating", "active", "error"
  created_at?: string;
  updated_at?: string;
}

export interface NodeChainCreateRequest {
  tag: string;
  name?: string;  // Phase 11-Fix.B: 可选，默认使用 tag
  description?: string;
  hops: string[];
  hop_protocols?: Record<string, string>;
  entry_rules?: Record<string, unknown>;
  relay_rules?: Record<string, unknown>;
  priority?: number;
  enabled?: boolean;
  // Multi-hop chain architecture v2 fields
  exit_egress?: string;  // Terminal node's local egress
  dscp_value?: number;  // DSCP marking value (1-63, auto-assigned if not provided)
  chain_mark_type?: ChainMarkType;  // "dscp" or "xray_email"
}

export interface NodeChainUpdateRequest {
  name?: string;
  description?: string;
  hops?: string[];
  hop_protocols?: Record<string, string>;
  entry_rules?: Record<string, unknown>;
  relay_rules?: Record<string, unknown>;
  priority?: number;
  enabled?: boolean;
  // Multi-hop chain architecture v2 fields
  exit_egress?: string;  // Terminal node's local egress
  dscp_value?: number;  // DSCP marking value (1-63)
  chain_mark_type?: ChainMarkType;  // "dscp" or "xray_email"
}

// Terminal egress info from remote node
export interface TerminalEgressInfo {
  tag: string;
  type: string;  // "pia", "custom", "warp", "direct", "openvpn", "v2ray"
  description?: string;
  enabled: boolean;
}

// Terminal egress list response (with cache support - Phase 11.5)
export interface TerminalEgressListResponse {
  egress_list: TerminalEgressInfo[];
  node_tag: string;
  cached?: boolean;          // Whether this is cached data
  cached_at?: string;        // ISO timestamp when cached
}

export interface NodeChainListResponse {
  chains: NodeChain[];
}

export interface ChainStats {
  tag: string;
  total_bytes: number;
  upload_bytes: number;
  download_bytes: number;
  active_connections: number;
  health_status: ChainHealthStatus;
  hop_latencies?: Record<string, number>;  // {node_tag: latency_ms}
}

export interface ChainStatsResponse {
  chains: Record<string, ChainStats>;
}

// Health check response with per-hop details
export interface ChainHopResult {
  hop: number;
  node: string;
  status: "connected" | "disconnected" | "connecting" | "error" | "unreachable" | "not_found" | "unknown";
  tunnel_type?: string;
  message?: string;
}

export interface ChainEgressCheckResult {
  exit_egress: string | null;
  status: "available" | "unavailable" | "not_configured" | "skipped" | "unknown";
  message: string | null;
}

export interface ChainHealthCheckResponse {
  chain: string;
  healthy: boolean;
  message: string;
  total_hops: number;
  hops: ChainHopResult[];
  egress_check?: ChainEgressCheckResult;
}


// Pairing Types
export interface GeneratePairRequestRequest {
  node_tag: string;
  node_description?: string;
  endpoint: string;
  tunnel_type: PeerTunnelType;
  bidirectional?: boolean;
  api_port?: number;
}

export interface GeneratePairRequestResponse {
  code: string;
  psk: string;
  pending_request: {
    node_tag: string;
    tunnel_type: string;
    bidirectional: boolean;
    xray_private_key?: string;
    xray_public_key?: string;
    xray_short_id?: string;
    wg_private_key?: string;
    wg_public_key?: string;
  };
}

export interface ImportPairRequestRequest {
  code: string;
  local_node_tag: string;
  local_node_description?: string;
  local_endpoint: string;
  api_port?: number;
}

export interface ImportPairRequestResponse {
  success: boolean;
  message: string;
  response_code: string | null;
  created_node_tag: string | null;
  tunnel_status: string | null;
  bidirectional: boolean | null;
}

export interface CompletePairingRequest {
  code: string;
  pending_request: Record<string, unknown>;
}

export interface CompletePairingResponse {
  success: boolean;
  message: string;
  created_node_tag: string | null;
}

export interface EnableInboundResponse {
  success: boolean;
  message: string;
  tag: string;
  inbound_port: number;
  inbound_uuid: string;
  reality_public_key: string;
  reality_short_id: string;
}

export interface DisableInboundResponse {
  success: boolean;
  message: string;
  tag: string;
}
// Updated types
