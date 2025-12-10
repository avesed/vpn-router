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

export interface GatewayStatus {
  timestamp: string;
  sing_box_running: boolean;
  wireguard_interface: Record<string, unknown>;
  config_mtime?: number;
  pia_profiles?: PiaProfile[];
}

export interface PiaProfile {
  name: string;
  description: string;
  region_id: string;
  dns_strategy: string;
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
  dns_strategy: string;
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
  type?: "custom" | "geosite" | "geoip";
}

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
}

export interface IngressResponse {
  interface: IngressInterface;
  peers: IngressPeer[];
  peer_count: number;
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
  type: "pia" | "custom";
  server?: string;
  port?: number;
  is_configured: boolean;
}

export interface AllEgressResponse {
  pia: EgressItem[];
  custom: EgressItem[];
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

// Backup / Restore
export interface BackupStatus {
  encryption_available: boolean;
  has_ingress: boolean;
  ingress_peer_count: number;
  custom_egress_count: number;
  pia_profile_count: number;
  has_pia_credentials: boolean;
  has_settings: boolean;
}

export interface BackupExportRequest {
  password?: string;
  include_pia_credentials: boolean;
}

export interface BackupExportResponse {
  message: string;
  backup: Record<string, unknown>;
  encrypted: boolean;
}

export interface BackupImportRequest {
  data: string;
  password?: string;
  merge_mode: "replace" | "merge";
}

export interface BackupImportResponse {
  message: string;
  results: {
    settings: boolean;
    ingress: boolean;
    custom_egress: boolean;
    pia_profiles: boolean;
    pia_credentials: boolean;
    custom_rules: boolean;
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
