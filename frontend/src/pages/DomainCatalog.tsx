import { useState, useEffect, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { DomainCategory, DomainListResponse, TypeBreakdownItem, CountryIpInfo, IpCatalogResponse } from "../types";
import {
  MagnifyingGlassIcon,
  GlobeAltIcon,
  PlusIcon,
  CheckIcon,
  XMarkIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ArrowPathIcon
} from "@heroicons/react/24/outline";

interface CategoryData {
  id: string;
  category: DomainCategory;
}

export default function DomainCatalog() {
  const { t } = useTranslation();
  const [categories, setCategories] = useState<CategoryData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<{ id: string; name: string }[]>([]);
  const [searching, setSearching] = useState(false);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [selectedLists, setSelectedLists] = useState<Set<string>>(new Set());
  const [availableOutbounds, setAvailableOutbounds] = useState<string[]>([]);
  const [selectedOutbound, setSelectedOutbound] = useState("");
  const [customTag, setCustomTag] = useState("");
  const [creating, setCreating] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [expandedList, setExpandedList] = useState<string | null>(null);
  const [listDetails, setListDetails] = useState<DomainListResponse | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [activeTab, setActiveTab] = useState<"type" | "ip">("type");

  // IP Catalog state
  const [ipCatalog, setIpCatalog] = useState<IpCatalogResponse | null>(null);
  const [ipSearchQuery, setIpSearchQuery] = useState("");
  const [ipSearchResults, setIpSearchResults] = useState<{ country_code: string; display_name: string }[]>([]);
  const [ipSearching, setIpSearching] = useState(false);
  const [selectedCountries, setSelectedCountries] = useState<Set<string>>(new Set());
  const [ipCustomTag, setIpCustomTag] = useState("");
  const [creatingIpRule, setCreatingIpRule] = useState(false);
  const [expandedCountry, setExpandedCountry] = useState<string | null>(null);
  const [countryDetails, setCountryDetails] = useState<CountryIpInfo | null>(null);
  const [loadingCountryDetails, setLoadingCountryDetails] = useState(false);

  // Add item to category modal state
  const [showAddItemModal, setShowAddItemModal] = useState(false);
  const [addItemCategoryId, setAddItemCategoryId] = useState("");
  const [addItemCategoryName, setAddItemCategoryName] = useState("");
  const [addItemName, setAddItemName] = useState("");
  const [addItemDomains, setAddItemDomains] = useState("");
  const [addingItem, setAddingItem] = useState(false);

  const loadCatalog = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [catalogRes, rulesRes, ipRes] = await Promise.all([
        api.getDomainCatalog(),
        api.getRouteRules(),
        api.getIpCatalog()
      ]);

      const categoryList: CategoryData[] = Object.entries(catalogRes.categories).map(
        ([id, category]) => ({ id, category })
      );
      setCategories(categoryList);
      setIpCatalog(ipRes);
      setAvailableOutbounds(rulesRes.available_outbounds);
      if (rulesRes.available_outbounds.length > 0) {
        setSelectedOutbound(rulesRes.available_outbounds[0]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load catalog");
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

    const timer = setTimeout(async () => {
      try {
        setSearching(true);
        const res = await api.searchDomainLists(searchQuery);
        setSearchResults(res.results);
      } catch {
        // ignore search errors
      } finally {
        setSearching(false);
      }
    }, 300);

    return () => clearTimeout(timer);
  }, [searchQuery]);

  // IP Search with debounce
  useEffect(() => {
    if (!ipSearchQuery.trim()) {
      setIpSearchResults([]);
      return;
    }

    const timer = setTimeout(async () => {
      try {
        setIpSearching(true);
        const res = await api.searchCountries(ipSearchQuery);
        setIpSearchResults(res.results);
      } catch {
        // ignore search errors
      } finally {
        setIpSearching(false);
      }
    }, 300);

    return () => clearTimeout(timer);
  }, [ipSearchQuery]);

  const toggleCategory = (categoryId: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(categoryId)) {
        next.delete(categoryId);
      } else {
        next.add(categoryId);
      }
      return next;
    });
  };

  const toggleListSelection = (listId: string) => {
    setSelectedLists((prev) => {
      const next = new Set(prev);
      if (next.has(listId)) {
        next.delete(listId);
      } else {
        next.add(listId);
      }
      return next;
    });
  };

  const selectAllInCategory = (category: DomainCategory) => {
    setSelectedLists((prev) => {
      const next = new Set(prev);
      category.lists.forEach((list) => next.add(list.id));
      return next;
    });
  };

  const selectTypeInRegion = (typeBreakdown: TypeBreakdownItem) => {
    setSelectedLists((prev) => {
      const next = new Set(prev);
      typeBreakdown.lists.forEach((listId) => next.add(listId));
      return next;
    });
  };

  const getTypeIcon = (typeId: string) => {
    const icons: Record<string, string> = {
      "streaming": "📺", "gaming": "🎮", "social": "💬", "ai": "🤖",
      "developer": "💻", "cloud": "☁️", "news": "📰", "ecommerce": "🛒",
      "communication": "📞", "cryptocurrency": "💰", "vpn-proxy": "🔐",
      "scholar": "📚", "education": "🎓", "pt-tracker": "🔗", "acg": "🎨",
      "novel": "📖", "adult": "🔞", "advertising": "🚫", "cloud-storage": "💾",
      "tech-companies": "🏢", "finance": "💳", "logistics": "🚚",
      "automotive": "🚗", "travel": "✈️", "enterprise": "📋",
      "network-tools": "🌐", "security": "🔒", "design": "🎨",
      "ipfs": "🌍", "forums": "💭", "media-tools": "📀", "url-shortener": "🔗",
      "wiki": "📕", "blogs": "✍️", "crowdfunding": "❤️", "android-apps": "📱",
      "weather": "🌤️", "olympiad": "🏆", "organizations": "🏛️"
    };
    return icons[typeId] || "📁";
  };

  const loadListDetails = async (listId: string) => {
    if (expandedList === listId) {
      setExpandedList(null);
      setListDetails(null);
      return;
    }

    try {
      setLoadingDetails(true);
      setExpandedList(listId);
      const details = await api.getDomainList(listId);
      setListDetails(details);
    } catch {
      // ignore
    } finally {
      setLoadingDetails(false);
    }
  };

  const createRule = async () => {
    if (selectedLists.size === 0 || !selectedOutbound) return;

    try {
      setCreating(true);
      setError(null);
      const res = await api.createQuickRule(
        Array.from(selectedLists),
        selectedOutbound,
        customTag || undefined
      );
      setSuccessMessage(res.message);
      setSelectedLists(new Set());
      setCustomTag("");

      // Clear success message after 3 seconds
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create rule");
    } finally {
      setCreating(false);
    }
  };

  // IP Catalog functions
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
      setLoadingCountryDetails(true);
      setExpandedCountry(cc);
      const details = await api.getCountryIps(cc);
      setCountryDetails(details);
    } catch {
      // ignore
    } finally {
      setLoadingCountryDetails(false);
    }
  };

  const createIpRule = async () => {
    if (selectedCountries.size === 0 || !selectedOutbound) return;

    try {
      setCreatingIpRule(true);
      setError(null);
      const res = await api.createIpQuickRule(
        Array.from(selectedCountries),
        selectedOutbound,
        ipCustomTag || undefined
      );
      setSuccessMessage(res.message);
      setSelectedCountries(new Set());
      setIpCustomTag("");

      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create rule");
    } finally {
      setCreatingIpRule(false);
    }
  };

  const getDisplayCountries = () => {
    if (!ipCatalog) return [];
    return Object.entries(ipCatalog.countries).sort((a, b) => a[1].display_name.localeCompare(b[1].display_name));
  };

  const openAddItemModal = (categoryId: string, categoryName: string) => {
    setAddItemCategoryId(categoryId);
    setAddItemCategoryName(categoryName);
    setAddItemName("");
    setAddItemDomains("");
    setShowAddItemModal(true);
  };

  const addItemToCategory = async () => {
    if (!addItemName.trim()) {
      setError(t('catalog.enterListName'));
      return;
    }

    const domains = addItemDomains.trim()
      .split(/[\n,]/)
      .map(s => s.trim())
      .filter(Boolean);

    if (domains.length === 0) {
      setError(t('catalog.enterAtLeastOneDomain'));
      return;
    }

    try {
      setAddingItem(true);
      setError(null);
      const res = await api.addCategoryItem(addItemCategoryId, addItemName.trim(), domains);
      setSuccessMessage(res.message);
      setShowAddItemModal(false);
      loadCatalog();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "添加失败");
    } finally {
      setAddingItem(false);
    }
  };

  const deleteCustomItem = async (categoryId: string, itemId: string) => {
    if (!confirm(t('catalog.confirmDeleteItem'))) return;

    try {
      setError(null);
      await api.deleteCategoryItem(categoryId, itemId);
      setSuccessMessage("已删除");
      loadCatalog();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "删除失败");
    }
  };

  const getCategoryIcon = (categoryId: string) => {
    const icons: Record<string, string> = {
      // === 按类型分类 ===
      "streaming": "📺",
      "gaming": "🎮",
      "social": "💬",
      "ai": "🤖",
      "developer": "💻",
      "cloud": "☁️",
      "news": "📰",
      "ecommerce": "🛒",
      "communication": "📞",
      "cryptocurrency": "💰",
      "vpn-proxy": "🔐",
      "scholar": "📚",
      "education": "🎓",
      "pt-tracker": "🔗",
      "acg": "🎨",
      "novel": "📖",
      "adult": "🔞",
      "advertising": "🚫",
      "cloud-storage": "💾",
      "tech-companies": "🏢",
      "finance": "💳",
      "logistics": "🚚",
      "automotive": "🚗",
      "travel": "✈️",
      "enterprise": "📋",
      "network-tools": "🌐",
      "security": "🔒",
      "design": "🎨",
      "ipfs": "🌍",
      "forums": "💭",
      "media-tools": "📀",
      "url-shortener": "🔗",
      "wiki": "📕",
      "blogs": "✍️",
      "crowdfunding": "❤️",
      "android-apps": "📱",
      "weather": "🌤️",
      "olympiad": "🏆",
      "organizations": "🏛️",
      // === 按地区分类 ===
      "region-cn": "🇨🇳",
      "region-jp": "🇯🇵",
      "region-us": "🇺🇸",
      "region-ir": "🇮🇷",
      "region-ru": "🇷🇺",
      "region-global": "🌍"
    };
    return icons[categoryId] || "📁";
  };

  // 获取翻译后的分类名称和描述（优先使用 i18n，fallback 到 API 数据）
  const getCategoryName = (categoryId: string, fallbackName: string): string => {
    const translationKey = `catalog.categories.${categoryId}.name`;
    const translated = t(translationKey);
    // 如果翻译键不存在，t() 会返回键本身
    return translated === translationKey ? fallbackName : translated;
  };

  const getCategoryDescription = (categoryId: string, fallbackDesc: string): string => {
    const translationKey = `catalog.categories.${categoryId}.description`;
    const translated = t(translationKey);
    return translated === translationKey ? fallbackDesc : translated;
  };

  // 获取翻译后的国家名称（优先使用 i18n，fallback 到 API 数据）
  const getCountryName = (countryCode: string, fallbackName: string): string => {
    const translationKey = `catalog.countries.${countryCode.toLowerCase()}`;
    const translated = t(translationKey);
    // 移除 emoji 前缀（如果有的话）
    let cleanFallback = fallbackName;
    if (fallbackName.includes(' ') && /[\u{1F1E0}-\u{1F1FF}]/u.test(fallbackName.split(' ')[0])) {
      cleanFallback = fallbackName.split(' ').slice(1).join(' ');
    }
    return translated === translationKey ? cleanFallback : translated;
  };

  // 过滤当前标签页的分类 (只显示按类型分类)
  const filteredCategories = categories.filter(
    ({ category }) => category.group === "type"
  );

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
          <h1 className="text-2xl font-bold text-white">{t('catalog.title')}</h1>
          <p className="text-slate-400 mt-1">
            {t('catalog.subtitle')}
            {activeTab === "ip" && ipCatalog && (
              <span className="ml-2 text-slate-500">
                ({t('catalog.countriesCount', { count: ipCatalog.stats.total_countries })})
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadCatalog}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
            title={t('common.refresh')}
          >
            <ArrowPathIcon className="h-5 w-5 text-slate-400" />
          </button>
        </div>
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

      {/* Tabs */}
      <div className="flex gap-2 p-1 rounded-xl bg-white/5 w-fit">
        <button
          onClick={() => setActiveTab("type")}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === "type"
              ? "bg-brand text-white"
              : "text-slate-400 hover:text-white hover:bg-white/5"
          }`}
        >
          📋 {t('catalog.byDomain')}
        </button>
        <button
          onClick={() => setActiveTab("ip")}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === "ip"
              ? "bg-brand text-white"
              : "text-slate-400 hover:text-white hover:bg-white/5"
          }`}
        >
          🌍 {t('catalog.byIp')}
        </button>
      </div>

      {/* Domain Search - only show in domain tab */}
      {activeTab === "type" && (
        <>
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t('catalog.searchDomainLists')}
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
              <h3 className="text-sm font-semibold text-slate-400 mb-3">{t('common.searchResults')}</h3>
              <div className="flex flex-wrap gap-2">
                {searchResults.map((result) => (
                  <button
                    key={result.id}
                    onClick={() => toggleListSelection(result.id)}
                    className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                      selectedLists.has(result.id)
                        ? "bg-brand text-white"
                        : "bg-white/10 text-slate-300 hover:bg-white/20"
                    }`}
                  >
                    {selectedLists.has(result.id) && <CheckIcon className="inline h-4 w-4 mr-1" />}
                    {result.name}
                  </button>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Selected Lists & Create Rule */}
      {selectedLists.size > 0 && (
        <div className="rounded-xl bg-gradient-to-r from-brand/20 to-blue-600/20 border border-brand/30 p-4">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-white mb-2">
                {t('catalog.selectedLists', { count: selectedLists.size })}
              </h3>
              <div className="flex flex-wrap gap-2 mb-4">
                {Array.from(selectedLists).map((listId) => (
                  <span
                    key={listId}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-white/10 text-sm text-slate-300"
                  >
                    {listId}
                    <button
                      onClick={() => toggleListSelection(listId)}
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
                  placeholder={t('catalog.customRuleName')}
                  className="px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white text-sm placeholder-slate-500 focus:outline-none focus:border-brand"
                />
                <button
                  onClick={createRule}
                  disabled={creating}
                  className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/80 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  {creating ? (
                    <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                  ) : (
                    <PlusIcon className="h-4 w-4" />
                  )}
                  {t('catalog.createRule')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Domain Categories (按域名 tab) */}
      {activeTab === "type" && (
        <div className="space-y-4">
          {filteredCategories.map(({ id, category }) => (
            <div
              key={id}
              className="rounded-xl bg-white/5 border border-white/10 overflow-hidden"
            >
              {/* Category Header */}
              <button
                onClick={() => toggleCategory(id)}
                className="w-full px-4 py-3 flex items-center justify-between hover:bg-white/5 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{getCategoryIcon(id)}</span>
                  <div className="text-left">
                    <h3 className="font-semibold text-white">{getCategoryName(id, category.name)}</h3>
                    <p className="text-sm text-slate-400">{getCategoryDescription(id, category.description)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="px-2 py-1 rounded-lg bg-white/10 text-xs text-slate-400">
                    {category.lists.length} {t('common.lists')}
                  </span>
                  {expandedCategories.has(id) ? (
                    <ChevronDownIcon className="h-5 w-5 text-slate-400" />
                  ) : (
                    <ChevronRightIcon className="h-5 w-5 text-slate-400" />
                  )}
                </div>
              </button>

              {/* Category Content */}
              {expandedCategories.has(id) && (
                <div className="px-4 pb-4 border-t border-white/10">
                  <div className="flex justify-between items-center py-2">
                  <button
                    onClick={() => openAddItemModal(id, getCategoryName(id, category.name))}
                    className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
                  >
                    <PlusIcon className="h-3 w-3" />
                    {t('catalog.addItem')}
                  </button>
                  <button
                    onClick={() => selectAllInCategory(category)}
                    className="text-xs text-brand hover:text-brand/80"
                  >
                    {t('catalog.selectAllCategory')}
                  </button>
                </div>
                <div className="grid gap-2">
                  {category.lists.map((list) => (
                    <div key={list.id}>
                      <div
                        className={`rounded-lg p-3 transition-colors ${
                          selectedLists.has(list.id)
                            ? "bg-brand/20 border border-brand/30"
                            : "bg-white/5 border border-transparent hover:bg-white/10"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <button
                              onClick={() => toggleListSelection(list.id)}
                              className={`w-5 h-5 rounded border flex items-center justify-center transition-colors ${
                                selectedLists.has(list.id)
                                  ? "bg-brand border-brand"
                                  : "border-slate-500 hover:border-brand"
                              }`}
                            >
                              {selectedLists.has(list.id) && (
                                <CheckIcon className="h-3 w-3 text-white" />
                              )}
                            </button>
                            <div>
                              <div className="flex items-center gap-2">
                                <GlobeAltIcon className="h-4 w-4 text-slate-400" />
                                <span className="font-medium text-white">{list.id}</span>
                                <span className="text-xs text-slate-500">
                                  {t('catalog.domainCount', { count: list.domain_count })}
                                </span>
                                {list.is_custom && (
                                  <span className="px-1.5 py-0.5 text-xs bg-emerald-500/20 text-emerald-400 rounded">
                                    {t('common.custom')}
                                  </span>
                                )}
                              </div>
                              {list.sample_domains.length > 0 && (
                                <p className="text-xs text-slate-500 mt-1 truncate max-w-md">
                                  {list.sample_domains.slice(0, 3).join(", ")}
                                  {list.sample_domains.length > 3 && "..."}
                                </p>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {list.is_custom && (
                              <button
                                onClick={() => deleteCustomItem(id, list.id)}
                                className="text-xs text-red-400 hover:text-red-300 px-2 py-1 rounded hover:bg-red-500/10"
                              >
                                {t('common.delete')}
                              </button>
                            )}
                            <button
                              onClick={() => loadListDetails(list.id)}
                              className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded hover:bg-white/10"
                            >
                              {expandedList === list.id ? t('common.collapse') : t('common.viewAll')}
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* List Details */}
                      {expandedList === list.id && (
                        <div className="mt-2 ml-8 p-3 rounded-lg bg-slate-800/50 border border-white/5">
                          {loadingDetails ? (
                            <div className="flex items-center gap-2 text-slate-400">
                              <div className="animate-spin h-4 w-4 border-2 border-brand border-t-transparent rounded-full" />
                              {t('common.loading')}
                            </div>
                          ) : listDetails ? (
                            <div className="space-y-2">
                              <h4 className="text-xs font-semibold text-slate-400">
                                {t('catalog.domainList')} ({listDetails.domains.length} {t('common.items')})
                              </h4>
                              <div className="max-h-48 overflow-y-auto">
                                <div className="flex flex-wrap gap-1">
                                  {listDetails.domains.slice(0, 100).map((domain) => (
                                    <span
                                      key={domain}
                                      className="px-2 py-0.5 rounded bg-white/5 text-xs text-slate-300 font-mono"
                                    >
                                      {domain}
                                    </span>
                                  ))}
                                  {listDetails.domains.length > 100 && (
                                    <span className="px-2 py-0.5 text-xs text-slate-500">
                                      ... {t('catalog.moreItems', { count: listDetails.domains.length - 100 })}
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
            )}
          </div>
          ))}
        </div>
      )}

      {/* IP Catalog (按IP tab) */}
      {activeTab === "ip" && (
        <div className="space-y-6">
          {/* IP Search */}
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
            <input
              type="text"
              value={ipSearchQuery}
              onChange={(e) => setIpSearchQuery(e.target.value)}
              placeholder={t('catalog.searchCountries')}
              className="w-full pl-12 pr-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand/50 focus:ring-1 focus:ring-brand/50"
            />
            {ipSearching && (
              <div className="absolute right-4 top-1/2 -translate-y-1/2">
                <div className="animate-spin h-4 w-4 border-2 border-brand border-t-transparent rounded-full" />
              </div>
            )}
          </div>

          {/* IP Search Results */}
          {ipSearchResults.length > 0 && (
            <div className="rounded-xl bg-white/5 border border-white/10 p-4">
              <h3 className="text-sm font-semibold text-slate-400 mb-3">{t('common.searchResults')}</h3>
              <div className="flex flex-wrap gap-2">
                {ipSearchResults.map((result) => (
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
                    <span className="font-medium">{result.country_code.toUpperCase()}</span>
                    <span className="ml-1">{getCountryName(result.country_code, result.display_name)}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Selected Countries & Create IP Rule */}
          {selectedCountries.size > 0 && (
            <div className="rounded-xl bg-gradient-to-r from-emerald-500/20 to-cyan-600/20 border border-emerald-500/30 p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <h3 className="text-sm font-semibold text-white mb-2">
                    {t('catalog.selectedCountries', { count: selectedCountries.size })}
                  </h3>
                  <div className="flex flex-wrap gap-2 mb-4">
                    {Array.from(selectedCountries).map((cc) => (
                      <span
                        key={cc}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-white/10 text-sm text-slate-300"
                      >
                        {getCountryName(cc, ipCatalog?.countries[cc]?.display_name || cc.toUpperCase())}
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
                      value={ipCustomTag}
                      onChange={(e) => setIpCustomTag(e.target.value)}
                      placeholder={t('catalog.customRuleName')}
                      className="px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white text-sm placeholder-slate-500 focus:outline-none focus:border-brand"
                    />
                    <button
                      onClick={createIpRule}
                      disabled={creatingIpRule}
                      className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                    >
                      {creatingIpRule ? (
                        <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                      ) : (
                        <PlusIcon className="h-4 w-4" />
                      )}
                      {t('catalog.createIpRule')}
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
                          <span className="font-medium text-white">{cc.toUpperCase()}</span>
                          <span className="text-slate-300">{getCountryName(cc, info.display_name)}</span>
                        </div>
                        <div className="flex items-center gap-2 text-xs text-slate-500">
                          <span>{info.ipv4_count.toLocaleString()} {t('catalog.ipv4')}</span>
                          <span>·</span>
                          <span>{info.ipv6_count.toLocaleString()} {t('catalog.ipv6')}</span>
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
                    {loadingCountryDetails ? (
                      <div className="flex items-center gap-2 text-slate-400 py-2">
                        <div className="animate-spin h-4 w-4 border-2 border-brand border-t-transparent rounded-full" />
                        {t('common.loading')}
                      </div>
                    ) : countryDetails ? (
                      <div className="space-y-2 pt-3">
                        <div className="flex items-center justify-between text-xs text-slate-400">
                          <span>{t('catalog.recommendedExit')}: {countryDetails.recommended_exit}</span>
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
                                ... {t('catalog.moreItems', { count: (countryDetails.ipv4_cidrs?.length || 0) - 50 })}
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
      )}

      {/* Add Item to Category Modal */}
      {showAddItemModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">
                  {t('catalog.addItemTo', { name: addItemCategoryName })}
                </h2>
                <button
                  onClick={() => setShowAddItemModal(false)}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t('catalog.listName')} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={addItemName}
                  onChange={(e) => setAddItemName(e.target.value)}
                  placeholder="例如: my-streaming-sites"
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t('catalog.domainList')} <span className="text-red-400">*</span>
                </label>
                <textarea
                  value={addItemDomains}
                  onChange={(e) => setAddItemDomains(e.target.value)}
                  placeholder="每行一个或用逗号分隔&#10;例如:&#10;example.com&#10;test.org"
                  rows={6}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-sm"
                />
                <p className="text-xs text-slate-500 mt-1">
                  添加的域名将作为独立列表归入"{addItemCategoryName}"分类
                </p>
              </div>
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => setShowAddItemModal(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={addItemToCategory}
                disabled={addingItem}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {addingItem ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : (
                  <PlusIcon className="h-4 w-4" />
                )}
                {t('common.add')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
