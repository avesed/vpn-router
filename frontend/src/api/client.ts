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
  RealityKeyPair
} from "../types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";
const TOKEN_KEY = "vpn_gateway_token";

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

async function request<T>(path: string, options: { method?: HttpMethod; body?: unknown } = {}): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY);

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  // 401 Unauthorized - 清除 token 并跳转到登录页
  if (response.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.href = "/login";
    throw new Error("Session expired");
  }

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `API request failed: ${response.status}`);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

/**
 * Fetch image (e.g., QR code) with authentication and return as blob URL
 * Browser's img src doesn't send Authorization header, so we need to fetch manually
 */
async function fetchImageAsBlob(path: string): Promise<string> {
  const token = localStorage.getItem(TOKEN_KEY);

  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers,
  });

  if (response.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.href = "/login";
    throw new Error("Session expired");
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch image: ${response.status}`);
  }

  const blob = await response.blob();
  return URL.createObjectURL(blob);
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
  createProfile: (tag: string, description: string, regionId: string) =>
    request<{ message: string; profile: VpnProfile }>("/profiles", {
      method: "POST",
      body: { tag, description, region_id: regionId }
    }),
  updateProfile: (tag: string, data: { description?: string; region_id?: string }) =>
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
  addIngressPeer: (name: string, publicKey?: string, allowLan?: boolean) =>
    request<IngressPeerCreateResponse>("/ingress/peers", {
      method: "POST",
      body: { name, public_key: publicKey, allow_lan: allowLan }
    }),
  deleteIngressPeer: (name: string) =>
    request<{ message: string }>(`/ingress/peers/${encodeURIComponent(name)}`, { method: "DELETE" }),
  getIngressPeerConfigUrl: (name: string, privateKey?: string) => {
    const params = privateKey ? `?private_key=${encodeURIComponent(privateKey)}` : "";
    return `${API_BASE}/ingress/peers/${encodeURIComponent(name)}/config${params}`;
  },
  getIngressPeerQrcode: (name: string, privateKey?: string) => {
    const params = privateKey ? `?private_key=${encodeURIComponent(privateKey)}` : "";
    return fetchImageAsBlob(`/ingress/peers/${encodeURIComponent(name)}/qrcode${params}`);
  },

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

  // Backup / Restore
  getBackupStatus: () => request<BackupStatus>("/backup/status"),
  exportBackup: (password?: string, includePiaCredentials = true) =>
    request<BackupExportResponse>("/backup/export", {
      method: "POST",
      body: { password, include_pia_credentials: includePiaCredentials }
    }),
  importBackup: (data: string, password?: string, mergeMode: "replace" | "merge" = "replace") =>
    request<BackupImportResponse>("/backup/import", {
      method: "POST",
      body: { data, password, merge_mode: mergeMode }
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
    request<RealityKeyPair>("/ingress/v2ray/reality/generate-keys", { method: "POST" })
};
