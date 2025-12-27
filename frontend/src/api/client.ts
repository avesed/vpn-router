import type {
  Endpoint,
  GatewayStatus,
  ProfilesStatusResponse,
  PiaLoginResponse,
  PiaRegionsResponse,
  ProfilesResponse,
  VpnProfile,
  RouteRulesResponse,
  RouteRule,
  DomainCatalogResponse,
  DomainCategoriesResponse,
  DomainCategory,
  DomainListResponse,
  DomainSearchResponse,
  QuickRuleResponse,
  IpCatalogResponse,
  CountryIpInfo,
  IpSearchResponse,
  IpQuickRuleResponse,
  IngressResponse,
  IngressPeerCreateResponse,
  SubnetInfo,
  SubnetUpdateResponse,
  AllEgressResponse,
  CustomEgressListResponse,
  CustomEgress,
  CustomEgressCreateRequest,
  WireGuardConfParseResult,
  BackupStatus,
  BackupExportResponse,
  BackupImportResponse,
  AdBlockRulesResponse,
  AdBlockRuleSet,
  AdBlockRuleSetCreateRequest,
  AdBlockToggleResponse,
  DirectEgress,
  DirectEgressCreateRequest,
  DirectEgressUpdateRequest,
  DirectEgressListResponse,
  OpenVPNEgress,
  OpenVPNEgressCreateRequest,
  OpenVPNEgressUpdateRequest,
  OpenVPNEgressListResponse,
  OpenVPNParseResult,
  OpenVPNTunnelStatus,
  DashboardStats,
  // V2Ray types
  V2RayEgress,
  V2RayEgressCreateRequest,
  V2RayEgressUpdateRequest,
  V2RayEgressListResponse,
  V2RayURIParseResult,
  V2RayInboundConfig,
  V2RayInboundUpdateRequest,
  V2RayUser,
  V2RayUserCreateRequest,
  V2RayUserUpdateRequest,
  V2RayInboundResponse,
  V2RayUserShareResponse,
  // Xray types
  XrayStatus,
  RealityKeyPair,
  // WARP types
  WarpEgress,
  WarpEgressRegisterRequest,
  WarpEgressUpdateRequest,
  WarpEgressEndpointRequest,
  WarpEgressLicenseRequest,
  WarpEgressListResponse,
  WarpEgressStatus,
  WarpEndpointTestRequest,
  WarpEndpointTestResponse,
  // Outbound Groups types
  OutboundGroup,
  OutboundGroupCreateRequest,
  OutboundGroupUpdateRequest,
  OutboundGroupListResponse,
  AvailableMembersResponse,
  GroupHealthCheckResponse
} from "../types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";
const TOKEN_KEY = "vpn_gateway_token";

// M8: 默认请求超时时间 (30秒)
const DEFAULT_TIMEOUT = 30000;

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

interface RequestOptions {
  method?: HttpMethod;
  body?: unknown;
  timeout?: number;
}

// L15 修复: JWT 格式验证正则 (header.payload.signature)
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY);

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // L15 修复: 验证 token 格式后再发送
  if (token && JWT_PATTERN.test(token)) {
    headers["Authorization"] = `Bearer ${token}`;
  } else if (token) {
    // Token 格式无效，清除并记录
    console.warn("Invalid token format detected, clearing token");
    localStorage.removeItem(TOKEN_KEY);
  }

  // M8: 使用 AbortController 实现请求超时
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout ?? DEFAULT_TIMEOUT);

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method: options.method ?? "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("Request timeout");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }

  // 401 Unauthorized - 清除 token 并跳转到登录页
  if (response.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.href = "/login";
    throw new Error("Session expired");
  }

  if (!response.ok) {
    const text = await response.text();
    // M21 修复: 安全处理错误信息，避免暴露服务器内部堆栈
    let safeMessage: string;
    if (response.status >= 500) {
      // 服务器错误 - 不暴露内部详情
      console.error(`Server error ${response.status}:`, text);
      safeMessage = "Server error, please try again later";
    } else if (response.status === 404) {
      safeMessage = "Resource not found";
    } else if (response.status === 403) {
      safeMessage = "Access denied";
    } else {
      // 4xx 客户端错误 - 可以显示后端消息（但限制长度）
      safeMessage = text?.slice(0, 200) || `Request failed: ${response.status}`;
    }
    throw new Error(safeMessage);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

/**
 * Fetch with authentication helper (M8: with timeout)
 */
async function fetchWithAuth(path: string, timeout: number = DEFAULT_TIMEOUT): Promise<Response> {
  const token = localStorage.getItem(TOKEN_KEY);

  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // M8: 使用 AbortController 实现请求超时
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method: "GET",
      headers,
      signal: controller.signal,
    });
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("Request timeout");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }

  if (response.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.href = "/login";
    throw new Error("Session expired");
  }

  return response;
}

/**
 * Fetch image (e.g., QR code) with authentication and return as blob URL
 * Browser's img src doesn't send Authorization header, so we need to fetch manually
 */
async function fetchImageAsBlob(path: string): Promise<string> {
  const response = await fetchWithAuth(path);

  if (!response.ok) {
    throw new Error(`Failed to fetch image: ${response.status}`);
  }

  const blob = await response.blob();
  return URL.createObjectURL(blob);
}

/**
 * Fetch text content with authentication (e.g., config files)
 */
async function fetchTextWithAuth(path: string): Promise<string> {
  const response = await fetchWithAuth(path);

  if (!response.ok) {
    throw new Error(`Failed to fetch: ${response.status}`);
  }

  return response.text();
}

export const api = {
  // Status
  getStatus: () => request<GatewayStatus>("/status"),
  getDashboardStats: (timeRange: "1m" | "1h" | "24h" = "1m") =>
    request<DashboardStats>(`/stats/dashboard?time_range=${timeRange}`),
  getEndpoints: () => request<{ endpoints: Endpoint[] }>("/endpoints"),
  updateEndpoint: (tag: string, payload: Partial<Endpoint>) =>
    request(`/endpoints/${tag}`, { method: "PUT", body: payload }),

  // PIA Auth
  piaLogin: (username: string, password: string) =>
    request<PiaLoginResponse>("/pia/login", {
      method: "POST",
      body: { username, password }
    }),

  // PIA Regions
  getPiaRegions: () => request<PiaRegionsResponse>("/pia/regions"),

  // PIA Credentials Status
  getPiaCredentialsStatus: () => request<{ has_credentials: boolean; message: string }>("/pia/credentials-status"),

  // Profiles (legacy status)
  getProfilesStatus: () => request<ProfilesStatusResponse>("/profiles/status"),

  // Profile Management
  getProfiles: () => request<ProfilesResponse>("/profiles"),
  createProfile: (tag: string, description: string, regionId: string, customDns?: string) =>
    request<{ message: string; profile: VpnProfile }>("/profiles", {
      method: "POST",
      body: { tag, description, region_id: regionId, custom_dns: customDns || null }
    }),
  updateProfile: (tag: string, data: { description?: string; region_id?: string; custom_dns?: string }) =>
    request<{ message: string }>(`/profiles/${tag}`, {
      method: "PUT",
      body: data
    }),
  deleteProfile: (tag: string) =>
    request<{ message: string }>(`/profiles/${tag}`, { method: "DELETE" }),
  reconnectProfile: (profileTag: string) =>
    request<{ message: string; reload?: { success: boolean; message: string; method?: string } }>("/profiles/reconnect", {
      method: "POST",
      body: { profile_tag: profileTag }
    }),

  // Route Rules
  getRouteRules: () => request<RouteRulesResponse>("/rules"),
  updateRouteRules: (rules: RouteRule[], defaultOutbound: string) =>
    request<{ message: string }>("/rules", {
      method: "PUT",
      body: { rules, default_outbound: defaultOutbound }
    }),

  // Default Outbound (Hot Switch)
  getDefaultOutbound: () =>
    request<{ outbound: string; available_outbounds: string[] }>("/outbound/default"),
  switchDefaultOutbound: (outbound: string) =>
    request<{
      message: string;
      outbound: string;
      hot_switch: boolean;
      reloaded?: boolean;
      error?: string;
    }>("/outbound/default", {
      method: "PUT",
      body: { outbound }
    }),

  // Ingress Outbound Binding (入口绑定出口)
  getWireGuardIngressOutbound: () =>
    request<{ outbound: string | null; global_default: string; available_outbounds: string[] }>(
      "/ingress/wireguard/outbound"
    ),
  setWireGuardIngressOutbound: (outbound: string | null) =>
    request<{
      success: boolean;
      message: string;
      outbound: string | null;
      reloaded: boolean;
      error?: string;
    }>("/ingress/wireguard/outbound", {
      method: "PUT",
      body: { outbound }
    }),
  getV2RayIngressOutbound: () =>
    request<{ outbound: string | null; global_default: string; available_outbounds: string[] }>(
      "/ingress/v2ray/outbound"
    ),
  setV2RayIngressOutbound: (outbound: string | null) =>
    request<{
      success: boolean;
      message: string;
      outbound: string | null;
      reloaded: boolean;
      error?: string;
    }>("/ingress/v2ray/outbound", {
      method: "PUT",
      body: { outbound }
    }),

  // Actions
  reloadSingbox: () => request<{ message: string; method?: string }>("/actions/reload", { method: "POST" }),

  // Domain Catalog
  getDomainCatalog: () => request<DomainCatalogResponse>("/domain-catalog"),
  getDomainCategories: () => request<DomainCategoriesResponse>("/domain-catalog/categories"),
  getDomainCategory: (categoryId: string) => request<DomainCategory>(`/domain-catalog/categories/${categoryId}`),
  getDomainList: (listId: string) => request<DomainListResponse>(`/domain-catalog/lists/${listId}`),
  searchDomainLists: (query: string) => request<DomainSearchResponse>(`/domain-catalog/search?q=${encodeURIComponent(query)}`),
  createQuickRule: (listIds: string[], outbound: string, tag?: string) =>
    request<QuickRuleResponse>("/domain-catalog/quick-rule", {
      method: "POST",
      body: { list_ids: listIds, outbound, tag }
    }),
  addCategoryItem: (categoryId: string, name: string, domains: string[]) =>
    request<{ message: string; item_id: string; domain_count: number; category_id: string }>(
      `/domain-catalog/categories/${categoryId}/items`,
      { method: "POST", body: { name, domains } }
    ),
  deleteCategoryItem: (categoryId: string, itemId: string) =>
    request<{ message: string }>(
      `/domain-catalog/categories/${categoryId}/items/${encodeURIComponent(itemId)}`,
      { method: "DELETE" }
    ),

  // IP Catalog
  getIpCatalog: () => request<IpCatalogResponse>("/ip-catalog"),
  getCountryIps: (countryCode: string) => request<CountryIpInfo>(`/ip-catalog/countries/${countryCode}`),
  searchCountries: (query: string) => request<IpSearchResponse>(`/ip-catalog/search?q=${encodeURIComponent(query)}`),
  createIpQuickRule: (countryCodes: string[], outbound: string, tag?: string, ipv4Only = true) =>
    request<IpQuickRuleResponse>("/ip-catalog/quick-rule", {
      method: "POST",
      body: { country_codes: countryCodes, outbound, tag, ipv4_only: ipv4Only }
    }),

  // Custom Rules
  addCustomRule: (tag: string, outbound: string, domains?: string[], domainKeywords?: string[], ipCidrs?: string[]) =>
    request<{ message: string; tag: string; outbound: string }>("/rules/custom", {
      method: "POST",
      body: { tag, outbound, domains, domain_keywords: domainKeywords, ip_cidrs: ipCidrs }
    }),
  deleteCustomRule: (tag: string) =>
    request<{ message: string }>(`/rules/custom/${encodeURIComponent(tag)}`, { method: "DELETE" }),

  // Ingress WireGuard
  getIngress: () => request<IngressResponse>("/ingress"),
  addIngressPeer: (name: string, publicKey?: string, allowLan?: boolean, defaultOutbound?: string) =>
    request<IngressPeerCreateResponse>("/ingress/peers", {
      method: "POST",
      body: { name, public_key: publicKey, allow_lan: allowLan, default_outbound: defaultOutbound }
    }),
  updateIngressPeer: (name: string, data: { name?: string; default_outbound?: string | null }) =>
    request<{ message: string; reload_status?: { success: boolean; message: string } }>(
      `/ingress/peers/${encodeURIComponent(name)}`,
      { method: "PUT", body: data }
    ),
  deleteIngressPeer: (name: string) =>
    request<{ message: string }>(`/ingress/peers/${encodeURIComponent(name)}`, { method: "DELETE" }),
  getIngressPeerConfig: (name: string, privateKey?: string) => {
    const params = privateKey ? `?private_key=${encodeURIComponent(privateKey)}` : "";
    return fetchTextWithAuth(`/ingress/peers/${encodeURIComponent(name)}/config${params}`);
  },
  getIngressPeerQrcode: (name: string, privateKey?: string) => {
    const params = privateKey ? `?private_key=${encodeURIComponent(privateKey)}` : "";
    return fetchImageAsBlob(`/ingress/peers/${encodeURIComponent(name)}/qrcode${params}`);
  },

  // Ingress Subnet Configuration
  getIngressSubnet: () => request<SubnetInfo>("/ingress/subnet"),
  updateIngressSubnet: (address: string, migratePeers: boolean = true) =>
    request<SubnetUpdateResponse>("/ingress/subnet", {
      method: "PUT",
      body: { address, migrate_peers: migratePeers }
    }),

  // Settings
  getSettings: () => request<{ server_endpoint: string; listen_port: number }>("/settings"),
  updateSettings: (serverEndpoint: string) =>
    request<{ message: string; settings: { server_endpoint: string } }>("/settings", {
      method: "PUT",
      body: { server_endpoint: serverEndpoint }
    }),
  detectIp: () => request<{ public_ip: string | null; lan_ip: string | null; message: string }>("/settings/detect-ip"),

  // Egress Management
  getAllEgress: () => request<AllEgressResponse>("/egress"),
  getCustomEgress: () => request<CustomEgressListResponse>("/egress/custom"),
  createCustomEgress: (data: CustomEgressCreateRequest) =>
    request<{ message: string; egress: CustomEgress }>("/egress/custom", {
      method: "POST",
      body: data
    }),
  updateCustomEgress: (tag: string, data: Partial<CustomEgressCreateRequest>) =>
    request<{ message: string; egress: CustomEgress }>(`/egress/custom/${encodeURIComponent(tag)}`, {
      method: "PUT",
      body: data
    }),
  deleteCustomEgress: (tag: string) =>
    request<{ message: string }>(`/egress/custom/${encodeURIComponent(tag)}`, { method: "DELETE" }),
  parseWireGuardConf: (content: string) =>
    request<WireGuardConfParseResult>("/egress/custom/parse", {
      method: "POST",
      body: { content }
    }),

  // Direct Egress Management (绑定特定接口/IP)
  getDirectEgress: () => request<DirectEgressListResponse>("/egress/direct"),
  getDirectEgressByTag: (tag: string) =>
    request<DirectEgress>(`/egress/direct/${encodeURIComponent(tag)}`),
  createDirectEgress: (data: DirectEgressCreateRequest) =>
    request<{ message: string; tag: string }>("/egress/direct", {
      method: "POST",
      body: data
    }),
  updateDirectEgress: (tag: string, data: DirectEgressUpdateRequest) =>
    request<{ message: string }>(`/egress/direct/${encodeURIComponent(tag)}`, {
      method: "PUT",
      body: data
    }),
  deleteDirectEgress: (tag: string) =>
    request<{ message: string }>(`/egress/direct/${encodeURIComponent(tag)}`, { method: "DELETE" }),

  // Direct Default (默认直连出口 DNS 配置)
  getDirectDefault: () => request<{ tag: string; type: string; description: string; dns_servers: string[]; is_default: boolean }>("/egress/direct-default"),
  updateDirectDefault: (dns_servers: string[]) =>
    request<{ success: boolean; message: string; dns_servers: string[] }>("/egress/direct-default", {
      method: "PUT",
      body: { dns_servers }
    }),

  // OpenVPN Egress Management (通过 SOCKS5 代理桥接)
  getOpenVPNEgress: () => request<OpenVPNEgressListResponse>("/egress/openvpn"),
  getOpenVPNEgressByTag: (tag: string) =>
    request<OpenVPNEgress>(`/egress/openvpn/${encodeURIComponent(tag)}`),
  createOpenVPNEgress: (data: OpenVPNEgressCreateRequest) =>
    request<{ message: string; egress: OpenVPNEgress }>("/egress/openvpn", {
      method: "POST",
      body: data
    }),
  updateOpenVPNEgress: (tag: string, data: OpenVPNEgressUpdateRequest) =>
    request<{ message: string; egress: OpenVPNEgress }>(`/egress/openvpn/${encodeURIComponent(tag)}`, {
      method: "PUT",
      body: data
    }),
  deleteOpenVPNEgress: (tag: string) =>
    request<{ message: string }>(`/egress/openvpn/${encodeURIComponent(tag)}`, { method: "DELETE" }),
  parseOpenVPNConfig: (content: string) =>
    request<OpenVPNParseResult>("/egress/openvpn/parse", {
      method: "POST",
      body: { content }
    }),
  getOpenVPNTunnelStatus: (tag: string) =>
    request<OpenVPNTunnelStatus>(`/egress/openvpn/${encodeURIComponent(tag)}/status`),

  // Egress Connection Test
  testEgress: (tag: string, timeout?: number) =>
    request<{ success: boolean; delay: number; message: string }>(
      `/test/egress/${encodeURIComponent(tag)}${timeout ? `?timeout=${timeout}` : ""}`
    ),

  // Egress Speed Test
  testEgressSpeed: (tag: string, size?: number, timeout?: number) =>
    request<{
      success: boolean;
      speed_mbps: number;
      download_bytes?: number;
      duration_sec?: number;
      message: string;
    }>(`/test/egress/${encodeURIComponent(tag)}/speed?size=${size || 10}&timeout=${timeout || 30}`),

  // Backup / Restore (v2.0: SQLCipher 加密数据库)
  getBackupStatus: () => request<BackupStatus>("/backup/status"),
  exportBackup: (password: string) =>
    request<BackupExportResponse>("/backup/export", {
      method: "POST",
      body: { password }
    }),
  importBackup: (data: string, password: string) =>
    request<BackupImportResponse>("/backup/import", {
      method: "POST",
      body: { data, password }
    }),

  // AdBlock Rule Sets
  getAdBlockRules: (category?: string) =>
    request<AdBlockRulesResponse>(`/adblock/rules${category ? `?category=${encodeURIComponent(category)}` : ""}`),
  getAdBlockRule: (tag: string) =>
    request<AdBlockRuleSet>(`/adblock/rules/${encodeURIComponent(tag)}`),
  toggleAdBlockRule: (tag: string) =>
    request<AdBlockToggleResponse>(`/adblock/rules/${encodeURIComponent(tag)}/toggle`, { method: "PUT" }),
  updateAdBlockRule: (tag: string, data: Partial<AdBlockRuleSetCreateRequest>) =>
    request<{ message: string }>(`/adblock/rules/${encodeURIComponent(tag)}`, {
      method: "PUT",
      body: data
    }),
  createAdBlockRule: (data: AdBlockRuleSetCreateRequest) =>
    request<{ message: string; tag: string }>("/adblock/rules", {
      method: "POST",
      body: data
    }),
  deleteAdBlockRule: (tag: string) =>
    request<{ message: string }>(`/adblock/rules/${encodeURIComponent(tag)}`, { method: "DELETE" }),
  applyAdBlockRules: () =>
    request<{ message: string; status: string }>("/adblock/apply", { method: "POST" }),

  // ============ V2Ray Egress Management ============
  getV2RayEgress: () => request<V2RayEgressListResponse>("/egress/v2ray"),
  getV2RayEgressByTag: (tag: string) =>
    request<V2RayEgress>(`/egress/v2ray/${encodeURIComponent(tag)}`),
  createV2RayEgress: (data: V2RayEgressCreateRequest) =>
    request<{ message: string; tag: string; id: number }>("/egress/v2ray", {
      method: "POST",
      body: data
    }),
  updateV2RayEgress: (tag: string, data: V2RayEgressUpdateRequest) =>
    request<{ message: string }>(`/egress/v2ray/${encodeURIComponent(tag)}`, {
      method: "PUT",
      body: data
    }),
  deleteV2RayEgress: (tag: string) =>
    request<{ message: string }>(`/egress/v2ray/${encodeURIComponent(tag)}`, { method: "DELETE" }),
  parseV2RayURI: (uri: string) =>
    request<V2RayURIParseResult>("/egress/v2ray/parse", {
      method: "POST",
      body: { uri }
    }),

  // ============ V2Ray Inbound Management ============
  getV2RayInbound: () => request<V2RayInboundResponse>("/ingress/v2ray"),
  updateV2RayInbound: (data: V2RayInboundUpdateRequest) =>
    request<{ message: string }>("/ingress/v2ray", {
      method: "PUT",
      body: data
    }),

  // V2Ray User Management
  addV2RayUser: (data: V2RayUserCreateRequest) =>
    request<{ message: string; id: number; uuid: string }>("/ingress/v2ray/users", {
      method: "POST",
      body: data
    }),
  updateV2RayUser: (userId: number, data: V2RayUserUpdateRequest) =>
    request<{ message: string }>(`/ingress/v2ray/users/${userId}`, {
      method: "PUT",
      body: data
    }),
  deleteV2RayUser: (userId: number) =>
    request<{ message: string }>(`/ingress/v2ray/users/${userId}`, { method: "DELETE" }),
  getV2RayUserShareUri: (userId: number) =>
    request<V2RayUserShareResponse>(`/ingress/v2ray/users/${userId}/share`),
  getV2RayUserQRCode: (userId: number) =>
    fetchImageAsBlob(`/ingress/v2ray/users/${userId}/qrcode`),
  getV2RayUsersOnline: () =>
    request<Record<string, { online: boolean; last_seen: number; upload: number; download: number }>>(
      "/ingress/v2ray/users/online"
    ),

  // ============ Xray Control (V2Ray Inbound via Xray) ============
  getXrayStatus: () => request<XrayStatus>("/ingress/v2ray/xray/status"),
  restartXray: () =>
    request<{ message: string; status: XrayStatus }>("/ingress/v2ray/xray/restart", { method: "POST" }),
  reloadXray: () =>
    request<{ message: string; status: XrayStatus }>("/ingress/v2ray/xray/reload", { method: "POST" }),
  generateRealityKeys: () =>
    request<RealityKeyPair>("/ingress/v2ray/reality/generate-keys", { method: "POST" }),

  // ============ WARP Egress Management (Cloudflare WARP via usque MASQUE) ============
  getWarpEgress: () => request<WarpEgressListResponse>("/egress/warp"),
  getWarpEgressByTag: (tag: string) =>
    request<WarpEgress>(`/egress/warp/${encodeURIComponent(tag)}`),
  registerWarpEgress: (data: WarpEgressRegisterRequest) =>
    request<{ message: string; tag: string; id: number; account_type: string }>("/egress/warp/register", {
      method: "POST",
      body: data
    }),
  updateWarpEgress: (tag: string, data: WarpEgressUpdateRequest) =>
    request<{ message: string }>(`/egress/warp/${encodeURIComponent(tag)}`, {
      method: "PUT",
      body: data
    }),
  deleteWarpEgress: (tag: string) =>
    request<{ message: string }>(`/egress/warp/${encodeURIComponent(tag)}`, { method: "DELETE" }),
  reregisterWarpEgress: (tag: string) =>
    request<{ message: string; account_type: string }>(`/egress/warp/${encodeURIComponent(tag)}/reregister`, {
      method: "POST",
      timeout: 60000  // 重新注册可能需要较长时间
    }),
  getWarpEgressStatus: (tag: string) =>
    request<WarpEgressStatus>(`/egress/warp/${encodeURIComponent(tag)}/status`),
  applyWarpLicense: (tag: string, data: WarpEgressLicenseRequest) =>
    request<{ message: string; account_type: string }>(`/egress/warp/${encodeURIComponent(tag)}/apply-license`, {
      method: "POST",
      body: data
    }),
  setWarpEndpoint: (tag: string, data: WarpEgressEndpointRequest) =>
    request<{ message: string }>(`/egress/warp/${encodeURIComponent(tag)}/endpoint`, {
      method: "PUT",
      body: data
    }),
  testWarpEndpoints: (data: WarpEndpointTestRequest) =>
    request<WarpEndpointTestResponse>("/egress/warp/endpoints/test", {
      method: "POST",
      body: data,
      timeout: 120000  // 优选可能需要较长时间
    }),

  // ============ Outbound Groups Management (ECMP Load Balancing) ============

  getOutboundGroups: (enabledOnly = false) =>
    request<OutboundGroupListResponse>(`/outbound-groups?enabled_only=${enabledOnly}`),

  getOutboundGroup: (tag: string) =>
    request<OutboundGroup>(`/outbound-groups/${encodeURIComponent(tag)}`),

  createOutboundGroup: (data: OutboundGroupCreateRequest) =>
    request<{ success: boolean; group: OutboundGroup; message: string }>("/outbound-groups", {
      method: "POST",
      body: data
    }),

  updateOutboundGroup: (tag: string, data: OutboundGroupUpdateRequest) =>
    request<{ success: boolean; group: OutboundGroup; message: string }>(
      `/outbound-groups/${encodeURIComponent(tag)}`,
      {
        method: "PUT",
        body: data
      }
    ),

  deleteOutboundGroup: (tag: string) =>
    request<{ success: boolean; message: string }>(
      `/outbound-groups/${encodeURIComponent(tag)}`,
      { method: "DELETE" }
    ),

  getAvailableMembers: () =>
    request<AvailableMembersResponse>("/outbound-groups/available-members"),

  triggerGroupHealthCheck: (tag: string) =>
    request<GroupHealthCheckResponse>(
      `/outbound-groups/${encodeURIComponent(tag)}/health-check`,
      { method: "POST", timeout: 60000 }  // 健康检查可能需要较长时间
    )
};
