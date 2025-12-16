import { useState, useEffect, useCallback } from "react";
import { api } from "../api/client";
import type { CountryIpInfo, IpCatalogResponse } from "../types";
import {
  MagnifyingGlassIcon,
  PlusIcon,
  CheckIcon,
  XMarkIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ArrowPathIcon,
  GlobeAltIcon
} from "@heroicons/react/24/outline";

export default function IpCatalog() {
  const [catalog, setCatalog] = useState<IpCatalogResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<{ country_code: string; display_name: string }[]>([]);
  const [searching, setSearching] = useState(false);
  const [selectedCountries, setSelectedCountries] = useState<Set<string>>(new Set());
  const [availableOutbounds, setAvailableOutbounds] = useState<string[]>([]);
  const [selectedOutbound, setSelectedOutbound] = useState("");
  const [customTag, setCustomTag] = useState("");
  const [creating, setCreating] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [expandedCountry, setExpandedCountry] = useState<string | null>(null);
  const [countryDetails, setCountryDetails] = useState<CountryIpInfo | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  const loadCatalog = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [ipRes, rulesRes] = await Promise.all([
        api.getIpCatalog(),
        api.getRouteRules()
      ]);
      setCatalog(ipRes);
      setAvailableOutbounds(rulesRes.available_outbounds);
      if (rulesRes.available_outbounds.length > 0) {
        setSelectedOutbound(rulesRes.available_outbounds[0]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load IP catalog");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCatalog();
  }, [loadCatalog]);

  // Search with debounce
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        setSearching(true);
        const res = await api.searchCountries(searchQuery);
        // 仅在组件未卸载时更新状态
        if (!cancelled) {
          setSearchResults(res.results);
        }
      } catch {
        // ignore search errors
      } finally {
        if (!cancelled) {
          setSearching(false);
        }
      }
    }, 300);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [searchQuery]);

  const toggleCountrySelection = (cc: string) => {
    setSelectedCountries((prev) => {
      const next = new Set(prev);
      if (next.has(cc)) {
        next.delete(cc);
      } else {
        next.add(cc);
      }
      return next;
    });
  };

  const loadCountryDetails = async (cc: string) => {
    if (expandedCountry === cc) {
      setExpandedCountry(null);
      setCountryDetails(null);
      return;
    }

    try {
      setLoadingDetails(true);
      setExpandedCountry(cc);
      const details = await api.getCountryIps(cc);
      setCountryDetails(details);
    } catch {
      // ignore
    } finally {
      setLoadingDetails(false);
    }
  };

  const createRule = async () => {
    if (selectedCountries.size === 0 || !selectedOutbound) return;

    try {
      setCreating(true);
      setError(null);
      const res = await api.createIpQuickRule(
        Array.from(selectedCountries),
        selectedOutbound,
        customTag || undefined
      );
      setSuccessMessage(res.message);
      setSelectedCountries(new Set());
      setCustomTag("");

      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create rule");
    } finally {
      setCreating(false);
    }
  };

  // Get countries to display
  const getDisplayCountries = () => {
    if (!catalog) return [];
    return Object.entries(catalog.countries).sort((a, b) => a[1].display_name.localeCompare(b[1].display_name));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-brand border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">IP 规则库</h1>
          <p className="text-slate-400 mt-1">
            按国家/地区创建 IP 路由规则
            {catalog && (
              <span className="ml-2 text-slate-500">
                ({catalog.stats.total_countries} 个国家/地区)
              </span>
            )}
          </p>
        </div>
        <button
          onClick={loadCatalog}
          className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
          title="刷新"
        >
          <ArrowPathIcon className="h-5 w-5 text-slate-400" />
        </button>
      </div>

      {/* Error/Success Messages */}
      {error && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-4 text-red-400">
          {error}
        </div>
      )}
      {successMessage && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/20 p-4 text-emerald-400 flex items-center gap-2">
          <CheckIcon className="h-5 w-5" />
          {successMessage}
        </div>
      )}

      {/* Search */}
      <div className="relative">
        <MagnifyingGlassIcon className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="搜索国家/地区... (如: cn, 中国, us, japan)"
          className="w-full pl-12 pr-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand/50 focus:ring-1 focus:ring-brand/50"
        />
        {searching && (
          <div className="absolute right-4 top-1/2 -translate-y-1/2">
            <div className="animate-spin h-4 w-4 border-2 border-brand border-t-transparent rounded-full" />
          </div>
        )}
      </div>

      {/* Search Results */}
      {searchResults.length > 0 && (
        <div className="rounded-xl bg-white/5 border border-white/10 p-4">
          <h3 className="text-sm font-semibold text-slate-400 mb-3">搜索结果</h3>
          <div className="flex flex-wrap gap-2">
            {searchResults.map((result) => (
              <button
                key={result.country_code}
                onClick={() => toggleCountrySelection(result.country_code)}
                className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                  selectedCountries.has(result.country_code)
                    ? "bg-brand text-white"
                    : "bg-white/10 text-slate-300 hover:bg-white/20"
                }`}
              >
                {selectedCountries.has(result.country_code) && <CheckIcon className="inline h-4 w-4 mr-1" />}
                {result.display_name}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Selected Countries & Create Rule */}
      {selectedCountries.size > 0 && (
        <div className="rounded-xl bg-gradient-to-r from-emerald-500/20 to-cyan-600/20 border border-emerald-500/30 p-4">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-white mb-2">
                已选择 {selectedCountries.size} 个国家/地区
              </h3>
              <div className="flex flex-wrap gap-2 mb-4">
                {Array.from(selectedCountries).map((cc) => (
                  <span
                    key={cc}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-white/10 text-sm text-slate-300"
                  >
                    {catalog?.countries[cc]?.display_name || cc.toUpperCase()}
                    <button
                      onClick={() => toggleCountrySelection(cc)}
                      className="hover:text-red-400"
                    >
                      <XMarkIcon className="h-4 w-4" />
                    </button>
                  </span>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <select
                  value={selectedOutbound}
                  onChange={(e) => setSelectedOutbound(e.target.value)}
                  className="px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white text-sm focus:outline-none focus:border-brand"
                >
                  {availableOutbounds.map((ob) => (
                    <option key={ob} value={ob} className="bg-slate-800">
                      {ob}
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  value={customTag}
                  onChange={(e) => setCustomTag(e.target.value)}
                  placeholder="自定义规则名称 (可选)"
                  className="px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white text-sm placeholder-slate-500 focus:outline-none focus:border-brand"
                />
                <button
                  onClick={createRule}
                  disabled={creating}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  {creating ? (
                    <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                  ) : (
                    <PlusIcon className="h-4 w-4" />
                  )}
                  创建 IP 规则
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Countries Grid */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {getDisplayCountries().map(([cc, info]) => (
          <div
            key={cc}
            className={`rounded-xl border transition-colors ${
              selectedCountries.has(cc)
                ? "bg-emerald-500/10 border-emerald-500/30"
                : "bg-white/5 border-white/10 hover:bg-white/10"
            }`}
          >
            <div className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => toggleCountrySelection(cc)}
                    className={`w-5 h-5 rounded border flex items-center justify-center transition-colors ${
                      selectedCountries.has(cc)
                        ? "bg-emerald-500 border-emerald-500"
                        : "border-slate-500 hover:border-emerald-500"
                    }`}
                  >
                    {selectedCountries.has(cc) && (
                      <CheckIcon className="h-3 w-3 text-white" />
                    )}
                  </button>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-lg">{info.display_name}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <span>{info.ipv4_count.toLocaleString()} IPv4</span>
                      <span>·</span>
                      <span>{info.ipv6_count.toLocaleString()} IPv6</span>
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => loadCountryDetails(cc)}
                  className="text-slate-400 hover:text-white p-1"
                >
                  {expandedCountry === cc ? (
                    <ChevronDownIcon className="h-5 w-5" />
                  ) : (
                    <ChevronRightIcon className="h-5 w-5" />
                  )}
                </button>
              </div>

              {/* Sample IPs */}
              {info.sample_ipv4 && info.sample_ipv4.length > 0 && (
                <div className="mt-2 text-xs text-slate-500 font-mono truncate">
                  {info.sample_ipv4.slice(0, 2).join(", ")}...
                </div>
              )}
            </div>

            {/* Expanded Details */}
            {expandedCountry === cc && (
              <div className="px-4 pb-4 border-t border-white/10">
                {loadingDetails ? (
                  <div className="flex items-center gap-2 text-slate-400 py-2">
                    <div className="animate-spin h-4 w-4 border-2 border-brand border-t-transparent rounded-full" />
                    加载中...
                  </div>
                ) : countryDetails ? (
                  <div className="space-y-2 pt-3">
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span>推荐出口: {countryDetails.recommended_exit}</span>
                    </div>
                    <div className="max-h-32 overflow-y-auto">
                      <div className="flex flex-wrap gap-1">
                        {countryDetails.ipv4_cidrs?.slice(0, 50).map((cidr) => (
                          <span
                            key={cidr}
                            className="px-2 py-0.5 rounded bg-white/5 text-xs text-slate-300 font-mono"
                          >
                            {cidr}
                          </span>
                        ))}
                        {(countryDetails.ipv4_cidrs?.length || 0) > 50 && (
                          <span className="px-2 py-0.5 text-xs text-slate-500">
                            ... 还有 {(countryDetails.ipv4_cidrs?.length || 0) - 50} 个
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
