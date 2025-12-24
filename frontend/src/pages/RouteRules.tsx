import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { RouteRule, VpnProfile } from "../types";
import { PROTOCOL_OPTIONS, NETWORK_OPTIONS } from "../types";
import {
  PlusIcon,
  TrashIcon,
  ArrowPathIcon,
  GlobeAltIcon,
  ServerStackIcon,
  TagIcon,
  CheckCircleIcon,
  SignalIcon,
  ServerIcon
} from "@heroicons/react/24/outline";

interface RuleFormData {
  tag: string;
  outbound: string;
  domains: string;
  domain_keywords: string;
  ip_cidrs: string;
  // 协议/端口匹配字段
  protocols: string[];
  network: string;
  ports: string;
  port_ranges: string;
}

const emptyRule: RuleFormData = {
  tag: "",
  outbound: "direct",
  domains: "",
  domain_keywords: "",
  ip_cidrs: "",
  protocols: [],
  network: "",
  ports: "",
  port_ranges: ""
};

export default function RouteRules() {
  const { t } = useTranslation();
  const [rules, setRules] = useState<RouteRule[]>([]);
  const [profiles, setProfiles] = useState<VpnProfile[]>([]);
  const [availableOutbounds, setAvailableOutbounds] = useState<string[]>([]);
  const [defaultOutbound, setDefaultOutbound] = useState("direct");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // New rule form
  const [showNewForm, setShowNewForm] = useState(false);
  const [newRule, setNewRule] = useState<RuleFormData>(emptyRule);

  // Edit mode
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [editRule, setEditRule] = useState<RuleFormData>(emptyRule);

  // 过滤广告拦截规则（以 __adblock__ 前缀开头的规则由广告拦截页面管理）
  const filterAdblockRules = (rules: RouteRule[]): RouteRule[] => {
    return rules.filter(rule => !rule.tag.startsWith("__adblock__"));
  };

  const fetchData = async () => {
    try {
      const [rulesData, profilesData] = await Promise.all([
        api.getRouteRules(),
        api.getProfiles()
      ]);
      // 过滤掉广告拦截规则，这些规则由广告拦截页面管理
      setRules(filterAdblockRules(rulesData.rules));
      setDefaultOutbound(rulesData.default_outbound);
      setAvailableOutbounds(rulesData.available_outbounds || []);
      setProfiles(profilesData.profiles);
      setError(null);
    } catch (err: unknown) {
      // L13 修复: 类型安全的错误处理
      setError(err instanceof Error ? err.message : "Failed to load data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const parseList = (str: string): string[] => {
    return str
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  };

  const parsePorts = (str: string): number[] => {
    return str
      .split(/[,\n]/)
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !isNaN(n) && n > 0 && n <= 65535);
  };

  const formatList = (arr?: string[]): string => {
    return arr?.join("\n") || "";
  };

  const formatPorts = (arr?: number[]): string => {
    return arr?.map(String).join(", ") || "";
  };

  const handleAddRule = () => {
    if (!newRule.tag) return;

    const rule: RouteRule = {
      tag: newRule.tag.startsWith("custom-") ? newRule.tag : `custom-${newRule.tag}`,
      outbound: newRule.outbound,
      domains: parseList(newRule.domains),
      domain_keywords: parseList(newRule.domain_keywords),
      ip_cidrs: parseList(newRule.ip_cidrs),
      // 协议/端口匹配字段
      protocols: newRule.protocols.length > 0 ? newRule.protocols : undefined,
      network: newRule.network || undefined,
      ports: parsePorts(newRule.ports).length > 0 ? parsePorts(newRule.ports) : undefined,
      port_ranges: parseList(newRule.port_ranges).length > 0 ? parseList(newRule.port_ranges) : undefined,
      type: newRule.protocols.length > 0 || newRule.network || newRule.ports || newRule.port_ranges ? "protocol" : "custom"
    };

    setRules([...rules, rule]);
    setNewRule(emptyRule);
    setShowNewForm(false);
  };

  const handleDeleteRule = (index: number) => {
    const rule = rules[index];
    if (!confirm(t('rules.confirmDeleteRule', { name: rule.tag }))) return;
    setRules(rules.filter((_, i) => i !== index));
  };

  const handleEditRule = (index: number) => {
    const rule = rules[index];
    setEditingIndex(index);
    setEditRule({
      tag: rule.tag,
      outbound: rule.outbound,
      domains: formatList(rule.domains),
      domain_keywords: formatList(rule.domain_keywords),
      ip_cidrs: formatList(rule.ip_cidrs),
      // 协议/端口匹配字段
      protocols: rule.protocols || [],
      network: rule.network || "",
      ports: formatPorts(rule.ports),
      port_ranges: formatList(rule.port_ranges)
    });
  };

  const handleSaveEdit = () => {
    if (editingIndex === null) return;

    const updatedRules = [...rules];
    updatedRules[editingIndex] = {
      tag: editRule.tag,
      outbound: editRule.outbound,
      domains: parseList(editRule.domains),
      domain_keywords: parseList(editRule.domain_keywords),
      ip_cidrs: parseList(editRule.ip_cidrs),
      // 协议/端口匹配字段
      protocols: editRule.protocols.length > 0 ? editRule.protocols : undefined,
      network: editRule.network || undefined,
      ports: parsePorts(editRule.ports).length > 0 ? parsePorts(editRule.ports) : undefined,
      port_ranges: parseList(editRule.port_ranges).length > 0 ? parseList(editRule.port_ranges) : undefined,
      type: editRule.protocols.length > 0 || editRule.network || editRule.ports || editRule.port_ranges ? "protocol" : "custom"
    };
    setRules(updatedRules);
    setEditingIndex(null);
    setEditRule(emptyRule);
  };

  const handleSaveAll = async () => {
    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      await api.updateRouteRules(rules, defaultOutbound);
      setSuccess(t('rules.rulesSaved'));
      setTimeout(() => setSuccess(null), 3000);
    } catch (err: unknown) {
      // L13 修复: 类型安全的错误处理
      setError(err instanceof Error ? err.message : "Failed to save rules");
    } finally {
      setSaving(false);
    }
  };

  // Build outbound options from available_outbounds (includes custom egress)
  // Use profiles map for descriptions where available
  const profileMap = new Map(profiles.map(p => [p.tag, p.description]));
  const outboundOptions = availableOutbounds.map(ob => {
    if (ob === "direct") return { value: "direct", label: `${t('common.direct')} (Direct)` };
    if (ob === "block") return { value: "block", label: `${t('common.block')} (Block)` };
    const description = profileMap.get(ob);
    return { value: ob, label: description ? `${ob} (${description})` : ob };
  });

  return (
    <div className="space-y-4 md:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-xl md:text-2xl font-bold text-white">{t('rules.title')}</h2>
          <p className="mt-1 text-xs md:text-sm text-slate-400">
            {t('rules.subtitle')}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={fetchData}
            disabled={loading}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors disabled:opacity-50"
            title={t('common.refresh')}
          >
            <ArrowPathIcon className={`h-5 w-5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={() => setShowNewForm(true)}
            className="flex items-center gap-2 px-3 md:px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm md:text-base font-medium transition-colors"
          >
            <PlusIcon className="h-5 w-5" />
            <span className="hidden sm:inline">{t('rules.addRule')}</span>
            <span className="sm:hidden">{t('common.add')}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-5 py-4">
          <p className="text-sm text-rose-300">{error}</p>
        </div>
      )}

      {success && (
        <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 px-5 py-4 flex items-center gap-3">
          <CheckCircleIcon className="h-5 w-5 text-emerald-400" />
          <p className="text-sm text-emerald-300">{success}</p>
        </div>
      )}

      {/* Default Outbound */}
      <div className="rounded-xl md:rounded-2xl border border-white/10 bg-slate-900/40 p-4 md:p-5">
        <div className="flex items-center gap-3 mb-3 md:mb-4">
          <div className="rounded-lg bg-blue-500/20 p-2">
            <ServerStackIcon className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white text-sm md:text-base">{t('rules.defaultOutbound')}</h3>
            <p className="text-xs text-slate-400">{t('rules.defaultOutboundDesc')}</p>
          </div>
        </div>
        <select
          value={defaultOutbound}
          onChange={(e) => setDefaultOutbound(e.target.value)}
          className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
        >
          {outboundOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>

      {/* New Rule Form */}
      {showNewForm && (
        <div className="rounded-xl md:rounded-2xl border border-brand/30 bg-brand/5 p-4 md:p-6">
          <h3 className="text-base md:text-lg font-semibold text-white mb-3 md:mb-4">{t('rules.addNewRule')}</h3>
          <div className="grid gap-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  {t('rules.ruleTag')} ({t('rules.ruleTagHint')})
                </label>
                <input
                  value={newRule.tag}
                  onChange={(e) =>
                    setNewRule({ ...newRule, tag: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "") })
                  }
                  className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                  placeholder="streaming-us"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  {t('rules.outboundLine')}
                </label>
                <select
                  value={newRule.outbound}
                  onChange={(e) => setNewRule({ ...newRule, outbound: e.target.value })}
                  className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                >
                  {outboundOptions.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t('rules.domainSuffix')} ({t('rules.domainSuffixHint')})
              </label>
              <textarea
                value={newRule.domains}
                onChange={(e) => setNewRule({ ...newRule, domains: e.target.value })}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                rows={3}
                placeholder="netflix.com&#10;nflxvideo.net"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t('rules.domainKeyword')} ({t('rules.domainKeywordHint')})
              </label>
              <textarea
                value={newRule.domain_keywords}
                onChange={(e) => setNewRule({ ...newRule, domain_keywords: e.target.value })}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                rows={2}
                placeholder="youtube&#10;googlevideo"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t('rules.ipCidr')} ({t('rules.ipCidrHint')})
              </label>
              <textarea
                value={newRule.ip_cidrs}
                onChange={(e) => setNewRule({ ...newRule, ip_cidrs: e.target.value })}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                rows={2}
                placeholder="8.8.8.0/24&#10;1.1.1.0/24"
              />
            </div>

            {/* 协议/端口匹配 - 流量类型嗅探 */}
            <div className="border-t border-white/10 pt-4 mt-2">
              <div className="flex items-center gap-2 mb-3">
                <SignalIcon className="h-4 w-4 text-purple-400" />
                <span className="text-sm font-medium text-purple-300">{t('rules.protocolMatching')}</span>
              </div>

              {/* 协议类型 (多选) */}
              <div className="mb-4">
                <label className="block text-xs font-medium text-slate-400 mb-2">
                  {t('rules.protocols')} ({t('rules.protocolsHint')})
                </label>
                <div className="flex flex-wrap gap-2">
                  {PROTOCOL_OPTIONS.map((opt) => (
                    <label
                      key={opt.value}
                      className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs cursor-pointer transition ${
                        newRule.protocols.includes(opt.value)
                          ? "bg-purple-500/30 text-purple-200 border border-purple-500/50"
                          : "bg-slate-800/60 text-slate-400 border border-transparent hover:bg-slate-800"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={newRule.protocols.includes(opt.value)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewRule({ ...newRule, protocols: [...newRule.protocols, opt.value] });
                          } else {
                            setNewRule({ ...newRule, protocols: newRule.protocols.filter(p => p !== opt.value) });
                          }
                        }}
                        className="sr-only"
                      />
                      <span>{opt.label}</span>
                      <span className="text-slate-500">({opt.description})</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* 网络类型 */}
              <div className="mb-4">
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  {t('rules.network')}
                </label>
                <select
                  value={newRule.network}
                  onChange={(e) => setNewRule({ ...newRule, network: e.target.value })}
                  className="w-full md:w-48 rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                >
                  {NETWORK_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label} - {opt.description}
                    </option>
                  ))}
                </select>
              </div>

              {/* 端口 */}
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    {t('rules.ports')} ({t('rules.portsHint')})
                  </label>
                  <input
                    value={newRule.ports}
                    onChange={(e) => setNewRule({ ...newRule, ports: e.target.value })}
                    className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                    placeholder="80, 443, 8080"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    {t('rules.portRanges')} ({t('rules.portRangesHint')})
                  </label>
                  <input
                    value={newRule.port_ranges}
                    onChange={(e) => setNewRule({ ...newRule, port_ranges: e.target.value })}
                    className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                    placeholder="6881:6889, 51413"
                  />
                </div>
              </div>
            </div>
          </div>
          <div className="mt-4 flex gap-3">
            <button
              onClick={handleAddRule}
              disabled={!newRule.tag}
              className="rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {t('common.add')}
            </button>
            <button
              onClick={() => {
                setShowNewForm(false);
                setNewRule(emptyRule);
              }}
              className="rounded-lg bg-white/10 px-4 py-2 text-sm text-slate-300"
            >
              {t('common.cancel')}
            </button>
          </div>
        </div>
      )}

      {/* Rules List */}
      {loading ? (
        <div className="flex justify-center py-12">
          <div className="h-10 w-10 animate-spin rounded-full border-4 border-slate-700 border-t-blue-500" />
        </div>
      ) : rules.length === 0 ? (
        <div className="rounded-xl md:rounded-2xl border border-white/5 bg-slate-900/40 p-8 md:p-12 text-center">
          <GlobeAltIcon className="mx-auto h-10 w-10 md:h-12 md:w-12 text-slate-600" />
          <p className="mt-3 md:mt-4 text-slate-400 text-sm md:text-base">{t('rules.noRulesConfigured')}</p>
          <p className="mt-2 text-xs md:text-sm text-slate-500">{t('rules.allTrafficDefault')}</p>
          <button
            onClick={() => setShowNewForm(true)}
            className="mt-4 rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white"
          >
            {t('rules.addFirstRule')}
          </button>
        </div>
      ) : (
        <div className="space-y-3 md:space-y-4">
          {rules.map((rule, index) => (
            <div
              key={rule.tag}
              className="rounded-xl md:rounded-2xl border border-white/5 bg-slate-900/40 p-4 md:p-5"
            >
              {editingIndex === index ? (
                // Edit mode
                <div className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {t('rules.ruleTag')}
                      </label>
                      <input
                        value={editRule.tag}
                        onChange={(e) => setEditRule({ ...editRule, tag: e.target.value })}
                        className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                        disabled
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {t('rules.outboundLine')}
                      </label>
                      <select
                        value={editRule.outbound}
                        onChange={(e) => setEditRule({ ...editRule, outbound: e.target.value })}
                        className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                      >
                        {outboundOptions.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">
                      {t('rules.domainSuffix')}
                    </label>
                    <textarea
                      value={editRule.domains}
                      onChange={(e) => setEditRule({ ...editRule, domains: e.target.value })}
                      className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                      rows={2}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">
                      {t('rules.domainKeyword')}
                    </label>
                    <textarea
                      value={editRule.domain_keywords}
                      onChange={(e) => setEditRule({ ...editRule, domain_keywords: e.target.value })}
                      className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                      rows={2}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">
                      {t('rules.ipCidr')}
                    </label>
                    <textarea
                      value={editRule.ip_cidrs}
                      onChange={(e) => setEditRule({ ...editRule, ip_cidrs: e.target.value })}
                      className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                      rows={2}
                    />
                  </div>

                  {/* 协议/端口匹配 - 编辑模式 */}
                  <div className="border-t border-white/10 pt-4">
                    <div className="flex items-center gap-2 mb-3">
                      <SignalIcon className="h-4 w-4 text-purple-400" />
                      <span className="text-sm font-medium text-purple-300">{t('rules.protocolMatching')}</span>
                    </div>

                    {/* 协议类型 (多选) */}
                    <div className="mb-4">
                      <label className="block text-xs font-medium text-slate-400 mb-2">
                        {t('rules.protocols')}
                      </label>
                      <div className="flex flex-wrap gap-2">
                        {PROTOCOL_OPTIONS.map((opt) => (
                          <label
                            key={opt.value}
                            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs cursor-pointer transition ${
                              editRule.protocols.includes(opt.value)
                                ? "bg-purple-500/30 text-purple-200 border border-purple-500/50"
                                : "bg-slate-800/60 text-slate-400 border border-transparent hover:bg-slate-800"
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={editRule.protocols.includes(opt.value)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setEditRule({ ...editRule, protocols: [...editRule.protocols, opt.value] });
                                } else {
                                  setEditRule({ ...editRule, protocols: editRule.protocols.filter(p => p !== opt.value) });
                                }
                              }}
                              className="sr-only"
                            />
                            <span>{opt.label}</span>
                          </label>
                        ))}
                      </div>
                    </div>

                    {/* 网络类型 */}
                    <div className="mb-4">
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {t('rules.network')}
                      </label>
                      <select
                        value={editRule.network}
                        onChange={(e) => setEditRule({ ...editRule, network: e.target.value })}
                        className="w-full md:w-48 rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                      >
                        {NETWORK_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* 端口 */}
                    <div className="grid gap-4 md:grid-cols-2">
                      <div>
                        <label className="block text-xs font-medium text-slate-400 mb-1">
                          {t('rules.ports')}
                        </label>
                        <input
                          value={editRule.ports}
                          onChange={(e) => setEditRule({ ...editRule, ports: e.target.value })}
                          className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                          placeholder="80, 443"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-400 mb-1">
                          {t('rules.portRanges')}
                        </label>
                        <input
                          value={editRule.port_ranges}
                          onChange={(e) => setEditRule({ ...editRule, port_ranges: e.target.value })}
                          className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white font-mono"
                          placeholder="6881:6889"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-3">
                    <button
                      onClick={handleSaveEdit}
                      className="rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white"
                    >
                      {t('common.save')}
                    </button>
                    <button
                      onClick={() => {
                        setEditingIndex(null);
                        setEditRule(emptyRule);
                      }}
                      className="rounded-lg bg-white/10 px-4 py-2 text-sm text-slate-300"
                    >
                      {t('common.cancel')}
                    </button>
                  </div>
                </div>
              ) : (
                // Display mode
                <>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="rounded-lg bg-slate-800 p-2">
                        <TagIcon className="h-5 w-5 text-slate-400" />
                      </div>
                      <div>
                        <h4 className="font-semibold text-white">{rule.tag}</h4>
                        <p className="text-sm text-slate-400">
                          {t('rules.outbound')}: <span className="text-blue-400">{rule.outbound}</span>
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-1">
                      <button
                        onClick={() => handleEditRule(index)}
                        className="rounded-lg p-2 text-slate-400 hover:bg-white/10 hover:text-white"
                        title={t('common.edit')}
                      >
                        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>
                      <button
                        onClick={() => handleDeleteRule(index)}
                        className="rounded-lg p-2 text-slate-400 hover:bg-rose-500/20 hover:text-rose-400"
                        title={t('common.delete')}
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-3 md:grid-cols-3">
                    {rule.domains && rule.domains.length > 0 && (
                      <div className="rounded-lg bg-black/20 p-3">
                        <p className="text-xs font-medium text-slate-500 mb-1">{t('rules.domainSuffix')}</p>
                        <div className="flex flex-wrap gap-1">
                          {rule.domains.slice(0, 5).map((d) => (
                            <span
                              key={d}
                              className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300 font-mono"
                            >
                              {d}
                            </span>
                          ))}
                          {rule.domains.length > 5 && (
                            <span className="text-xs text-slate-500">+{rule.domains.length - 5}</span>
                          )}
                        </div>
                      </div>
                    )}
                    {rule.domain_keywords && rule.domain_keywords.length > 0 && (
                      <div className="rounded-lg bg-black/20 p-3">
                        <p className="text-xs font-medium text-slate-500 mb-1">{t('rules.domainKeyword')}</p>
                        <div className="flex flex-wrap gap-1">
                          {rule.domain_keywords.slice(0, 5).map((k) => (
                            <span
                              key={k}
                              className="rounded bg-amber-500/20 px-2 py-0.5 text-xs text-amber-300 font-mono"
                            >
                              *{k}*
                            </span>
                          ))}
                          {rule.domain_keywords.length > 5 && (
                            <span className="text-xs text-slate-500">+{rule.domain_keywords.length - 5}</span>
                          )}
                        </div>
                      </div>
                    )}
                    {rule.ip_cidrs && rule.ip_cidrs.length > 0 && (
                      <div className="rounded-lg bg-black/20 p-3">
                        <p className="text-xs font-medium text-slate-500 mb-1">{t('rules.ipCidr')}</p>
                        <div className="flex flex-wrap gap-1">
                          {rule.ip_cidrs.slice(0, 3).map((ip) => (
                            <span
                              key={ip}
                              className="rounded bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-300 font-mono"
                            >
                              {ip}
                            </span>
                          ))}
                          {rule.ip_cidrs.length > 3 && (
                            <span className="text-xs text-slate-500">+{rule.ip_cidrs.length - 3}</span>
                          )}
                        </div>
                      </div>
                    )}
                    {/* 协议类型显示 */}
                    {rule.protocols && rule.protocols.length > 0 && (
                      <div className="rounded-lg bg-black/20 p-3">
                        <p className="text-xs font-medium text-slate-500 mb-1">{t('rules.protocols')}</p>
                        <div className="flex flex-wrap gap-1">
                          {rule.protocols.map((p) => (
                            <span
                              key={p}
                              className="rounded bg-purple-500/20 px-2 py-0.5 text-xs text-purple-300 font-mono"
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {/* 网络类型显示 */}
                    {rule.network && (
                      <div className="rounded-lg bg-black/20 p-3">
                        <p className="text-xs font-medium text-slate-500 mb-1">{t('rules.network')}</p>
                        <span className="rounded bg-cyan-500/20 px-2 py-0.5 text-xs text-cyan-300 font-mono uppercase">
                          {rule.network}
                        </span>
                      </div>
                    )}
                    {/* 端口显示 */}
                    {rule.ports && rule.ports.length > 0 && (
                      <div className="rounded-lg bg-black/20 p-3">
                        <p className="text-xs font-medium text-slate-500 mb-1">{t('rules.ports')}</p>
                        <div className="flex flex-wrap gap-1">
                          {rule.ports.slice(0, 5).map((port) => (
                            <span
                              key={port}
                              className="rounded bg-orange-500/20 px-2 py-0.5 text-xs text-orange-300 font-mono"
                            >
                              {port}
                            </span>
                          ))}
                          {rule.ports.length > 5 && (
                            <span className="text-xs text-slate-500">+{rule.ports.length - 5}</span>
                          )}
                        </div>
                      </div>
                    )}
                    {/* 端口范围显示 */}
                    {rule.port_ranges && rule.port_ranges.length > 0 && (
                      <div className="rounded-lg bg-black/20 p-3">
                        <p className="text-xs font-medium text-slate-500 mb-1">{t('rules.portRanges')}</p>
                        <div className="flex flex-wrap gap-1">
                          {rule.port_ranges.map((range) => (
                            <span
                              key={range}
                              className="rounded bg-orange-500/20 px-2 py-0.5 text-xs text-orange-300 font-mono"
                            >
                              {range}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Save Button - Always visible to save default outbound */}
      <div className="flex justify-end">
        <button
          onClick={handleSaveAll}
          disabled={saving}
          className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-brand to-blue-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-brand/20 transition hover:shadow-xl hover:shadow-brand/30 disabled:opacity-50"
        >
          {saving ? (
            <>
              <ArrowPathIcon className="h-4 w-4 animate-spin" />
              {t('common.saving')}
            </>
          ) : (
            <>
              <CheckCircleIcon className="h-4 w-4" />
              {t('rules.saveAndApply')}
            </>
          )}
        </button>
      </div>

      {/* Help Info */}
      <div className="rounded-xl md:rounded-2xl border border-blue-500/20 bg-blue-500/5 p-4 md:p-5">
        <h4 className="font-semibold text-blue-200 text-sm md:text-base mb-2">{t('rules.ruleExplanation')}</h4>
        <ul className="text-xs text-blue-300/80 space-y-1">
          <li>• {t('rules.ruleExplanationItems.domainSuffix')}</li>
          <li>• {t('rules.ruleExplanationItems.domainKeyword')}</li>
          <li>• {t('rules.ruleExplanationItems.ipCidr')}</li>
          <li>• {t('rules.ruleExplanationItems.protocol')}</li>
          <li>• {t('rules.ruleExplanationItems.port')}</li>
          <li>• {t('rules.ruleExplanationItems.order')}</li>
          <li>• {t('rules.ruleExplanationItems.default')}</li>
        </ul>
      </div>
    </div>
  );
}
