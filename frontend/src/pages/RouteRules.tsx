import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { RouteRule, VpnProfile } from "../types";
import {
  PlusIcon,
  TrashIcon,
  ArrowPathIcon,
  GlobeAltIcon,
  ServerStackIcon,
  TagIcon,
  CheckCircleIcon
} from "@heroicons/react/24/outline";

interface RuleFormData {
  tag: string;
  outbound: string;
  domains: string;
  domain_keywords: string;
  ip_cidrs: string;
}

const emptyRule: RuleFormData = {
  tag: "",
  outbound: "direct",
  domains: "",
  domain_keywords: "",
  ip_cidrs: ""
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
      setError((err as Error).message);
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

  const formatList = (arr?: string[]): string => {
    return arr?.join("\n") || "";
  };

  const handleAddRule = () => {
    if (!newRule.tag) return;

    const rule: RouteRule = {
      tag: newRule.tag.startsWith("custom-") ? newRule.tag : `custom-${newRule.tag}`,
      outbound: newRule.outbound,
      domains: parseList(newRule.domains),
      domain_keywords: parseList(newRule.domain_keywords),
      ip_cidrs: parseList(newRule.ip_cidrs),
      type: "custom"
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
      ip_cidrs: formatList(rule.ip_cidrs)
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
      type: "custom"
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
      setError((err as Error).message);
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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">{t('rules.title')}</h2>
          <p className="mt-1 text-sm text-slate-400">
            {t('rules.subtitle')}
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl bg-white/5 px-4 py-2 text-sm text-slate-300 transition hover:bg-white/10 disabled:opacity-50"
          >
            <ArrowPathIcon className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            {t('common.refresh')}
          </button>
          <button
            onClick={() => setShowNewForm(true)}
            className="flex items-center gap-2 rounded-xl bg-brand px-4 py-2 text-sm font-medium text-white transition hover:bg-brand/90"
          >
            <PlusIcon className="h-4 w-4" />
            {t('rules.addRule')}
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
      <div className="rounded-2xl border border-white/10 bg-slate-900/40 p-5">
        <div className="flex items-center gap-3 mb-4">
          <div className="rounded-lg bg-blue-500/20 p-2">
            <ServerStackIcon className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">{t('rules.defaultOutbound')}</h3>
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
        <div className="rounded-2xl border border-brand/30 bg-brand/5 p-6">
          <h3 className="text-lg font-semibold text-white mb-4">{t('rules.addNewRule')}</h3>
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
        <div className="rounded-2xl border border-white/5 bg-slate-900/40 p-12 text-center">
          <GlobeAltIcon className="mx-auto h-12 w-12 text-slate-600" />
          <p className="mt-4 text-slate-400">{t('rules.noRulesConfigured')}</p>
          <p className="mt-2 text-sm text-slate-500">{t('rules.allTrafficDefault')}</p>
          <button
            onClick={() => setShowNewForm(true)}
            className="mt-4 rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white"
          >
            {t('rules.addFirstRule')}
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {rules.map((rule, index) => (
            <div
              key={rule.tag}
              className="rounded-2xl border border-white/5 bg-slate-900/40 p-5"
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
      <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-5">
        <h4 className="font-semibold text-blue-200 mb-2">{t('rules.ruleExplanation')}</h4>
        <ul className="text-xs text-blue-300/80 space-y-1">
          <li>• {t('rules.ruleExplanationItems.domainSuffix')}</li>
          <li>• {t('rules.ruleExplanationItems.domainKeyword')}</li>
          <li>• {t('rules.ruleExplanationItems.ipCidr')}</li>
          <li>• {t('rules.ruleExplanationItems.order')}</li>
          <li>• {t('rules.ruleExplanationItems.default')}</li>
        </ul>
      </div>
    </div>
  );
}
