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
  AdBlockToggleResponse
} from "../types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

async function request<T>(path: string, options: { method?: HttpMethod; body?: unknown } = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method ?? "GET",
    headers: {
      "Content-Type": "application/json"
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `API request failed: ${response.status}`);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

export const api = {
  // Status
  getStatus: () => request<GatewayStatus>("/status"),
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
  addIngressPeer: (name: string, publicKey?: string) =>
    request<IngressPeerCreateResponse>("/ingress/peers", {
      method: "POST",
      body: { name, public_key: publicKey }
    }),
  deleteIngressPeer: (name: string) =>
    request<{ message: string }>(`/ingress/peers/${encodeURIComponent(name)}`, { method: "DELETE" }),
  getIngressPeerConfigUrl: (name: string, privateKey?: string) => {
    const params = privateKey ? `?private_key=${encodeURIComponent(privateKey)}` : "";
    return `${API_BASE}/ingress/peers/${encodeURIComponent(name)}/config${params}`;
  },
  getIngressPeerQrcodeUrl: (name: string, privateKey?: string) => {
    const params = privateKey ? `?private_key=${encodeURIComponent(privateKey)}` : "";
    return `${API_BASE}/ingress/peers/${encodeURIComponent(name)}/qrcode${params}`;
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
    request<{ message: string; status: string }>("/adblock/apply", { method: "POST" })
};
