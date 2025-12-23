import { useState, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { AdBlockRuleSet, AdBlockRuleSetCreateRequest } from "../types";
import {
  PlusIcon,
  TrashIcon,
  ArrowPathIcon,
  ShieldExclamationIcon,
  XMarkIcon,
  CheckIcon,
  PencilIcon,
  GlobeAltIcon,
  PlayIcon
} from "@heroicons/react/24/outline";

type TabType = "all" | "general" | "privacy" | "regional" | "security";

const CATEGORY_INFO: Record<string, { icon: string; color: string }> = {
  general: { icon: "shield", color: "blue" },
  privacy: { icon: "eye", color: "purple" },
  regional: { icon: "globe", color: "green" },
  security: { icon: "lock", color: "red" },
  antiadblock: { icon: "ban", color: "orange" }
};

export default function AdBlock() {
  const { t } = useTranslation();
  const [rules, setRules] = useState<AdBlockRuleSet[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("all");
  const [enabledCount, setEnabledCount] = useState(0);

  // Add modal state
  const [showAddModal, setShowAddModal] = useState(false);
  const [formTag, setFormTag] = useState("");
  const [formName, setFormName] = useState("");
  const [formUrl, setFormUrl] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formFormat, setFormFormat] = useState<"adblock" | "hosts" | "domains">("adblock");
  const [formCategory, setFormCategory] = useState("general");
  const [formRegion, setFormRegion] = useState("");

  // Edit modal state
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingRule, setEditingRule] = useState<AdBlockRuleSet | null>(null);

  const loadRules = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getAdBlockRules();
      setRules(data.rules);
      setEnabledCount(data.enabled_count);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("adblock.loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const resetForm = () => {
    setFormTag("");
    setFormName("");
    setFormUrl("");
    setFormDescription("");
    setFormFormat("adblock");
    setFormCategory("general");
    setFormRegion("");
  };

  const handleToggle = async (tag: string) => {
    setActionLoading(`toggle-${tag}`);
    try {
      await api.toggleAdBlockRule(tag);
      await loadRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.updateFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (tag: string) => {
    if (!confirm(t("adblock.confirmDelete", { tag }))) return;

    setActionLoading(`delete-${tag}`);
    try {
      await api.deleteAdBlockRule(tag);
      setSuccessMessage(t("adblock.deleteSuccess", { tag }));
      await loadRules();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.deleteFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleCreate = async () => {
    if (!formTag.trim() || !formName.trim() || !formUrl.trim()) {
      setError(t("adblock.fillRequiredFields"));
      return;
    }

    setActionLoading("create");
    try {
      const data: AdBlockRuleSetCreateRequest = {
        tag: formTag.trim().toLowerCase().replace(/[^a-z0-9-]/g, "-"),
        name: formName.trim(),
        url: formUrl.trim(),
        description: formDescription.trim(),
        format: formFormat,
        category: formCategory,
        region: formRegion.trim() || undefined
      };
      await api.createAdBlockRule(data);
      setSuccessMessage(t("adblock.createSuccess"));
      setShowAddModal(false);
      resetForm();
      await loadRules();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.createFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleEdit = (rule: AdBlockRuleSet) => {
    setEditingRule(rule);
    setFormTag(rule.tag);
    setFormName(rule.name);
    setFormUrl(rule.url);
    setFormDescription(rule.description);
    setFormFormat(rule.format);
    setFormCategory(rule.category);
    setFormRegion(rule.region || "");
    setShowEditModal(true);
  };

  const handleUpdate = async () => {
    if (!editingRule) return;

    setActionLoading("update");
    try {
      await api.updateAdBlockRule(editingRule.tag, {
        name: formName.trim(),
        url: formUrl.trim(),
        description: formDescription.trim(),
        format: formFormat,
        category: formCategory,
        region: formRegion.trim() || undefined
      });
      setSuccessMessage(t("adblock.updateSuccess"));
      setShowEditModal(false);
      setEditingRule(null);
      resetForm();
      await loadRules();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.updateFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleApply = async () => {
    setActionLoading("apply");
    try {
      await api.applyAdBlockRules();
      setSuccessMessage(t("adblock.applySuccess"));
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("adblock.applyFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const filteredRules = activeTab === "all"
    ? rules
    : rules.filter(r => r.category === activeTab);

  const categoryCount = (cat: string) => rules.filter(r => r.category === cat).length;

  if (loading && rules.length === 0) {
    return (
      <div className="flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-brand border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-[calc(100vh-12rem)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4 md:mb-6">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-white">{t("adblock.title")}</h1>
          <p className="text-xs md:text-sm text-slate-400 mt-1">{t("adblock.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleApply}
            disabled={actionLoading === "apply" || enabledCount === 0}
            className="flex items-center gap-2 px-3 md:px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium transition-colors disabled:opacity-50"
            title={t("adblock.applyTooltip")}
          >
            {actionLoading === "apply" ? (
              <ArrowPathIcon className="h-4 w-4 animate-spin" />
            ) : (
              <PlayIcon className="h-4 w-4" />
            )}
            <span className="hidden sm:inline">{t("adblock.apply")}</span>
          </button>
          <button
            onClick={() => {
              resetForm();
              setShowAddModal(true);
            }}
            className="flex items-center gap-2 px-3 md:px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors"
          >
            <PlusIcon className="h-4 w-4" />
            <span className="hidden sm:inline">{t("adblock.addRule")}</span>
          </button>
          <button
            onClick={loadRules}
            disabled={loading}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors disabled:opacity-50"
            title={t("common.refresh")}
          >
            <ArrowPathIcon className={`h-5 w-5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-4 text-red-400 mb-4">
          {error}
          <button onClick={() => setError(null)} className="float-right">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
      )}
      {successMessage && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/20 p-4 text-emerald-400 flex items-center gap-2 mb-4">
          <CheckIcon className="h-5 w-5" />
          {successMessage}
        </div>
      )}

      {/* Stats Bar */}
      <div className="grid grid-cols-3 gap-2 md:gap-4 mb-4 md:mb-6">
        <div className="rounded-xl bg-white/5 border border-white/10 p-3 md:p-4">
          <div className="text-xs md:text-sm text-slate-400">{t("adblock.totalRules")}</div>
          <div className="text-lg md:text-2xl font-bold text-white">{rules.length}</div>
        </div>
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/20 p-3 md:p-4">
          <div className="text-xs md:text-sm text-emerald-400">{t("adblock.enabledRules")}</div>
          <div className="text-lg md:text-2xl font-bold text-emerald-400">{enabledCount}</div>
        </div>
        <div className="rounded-xl bg-slate-500/10 border border-slate-500/20 p-3 md:p-4">
          <div className="text-xs md:text-sm text-slate-400">{t("adblock.disabledRules")}</div>
          <div className="text-lg md:text-2xl font-bold text-slate-400">{rules.length - enabledCount}</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-white/10 pb-2 mb-4 md:mb-6 overflow-x-auto scrollbar-hide">
        {[
          { key: "all", label: `${t("common.all")} (${rules.length})` },
          { key: "general", label: `${t("adblock.categories.general")} (${categoryCount("general")})` },
          { key: "privacy", label: `${t("adblock.categories.privacy")} (${categoryCount("privacy")})` },
          { key: "regional", label: `${t("adblock.categories.regional")} (${categoryCount("regional")})` },
          { key: "security", label: `${t("adblock.categories.security")} (${categoryCount("security")})` }
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as TabType)}
            className={`px-3 md:px-4 py-2 text-xs md:text-sm font-medium rounded-lg transition-colors whitespace-nowrap ${
              activeTab === tab.key
                ? "bg-brand text-white"
                : "text-slate-400 hover:text-white hover:bg-white/5"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Rules List */}
      {filteredRules.length === 0 ? (
        <div className="flex-1 rounded-xl bg-white/5 border border-white/10 p-12 text-center flex flex-col items-center justify-center">
          <ShieldExclamationIcon className="h-12 w-12 text-slate-600 mb-4" />
          <p className="text-slate-400">{t("adblock.noRules")}</p>
          <button
            onClick={() => {
              resetForm();
              setShowAddModal(true);
            }}
            className="mt-4 px-4 py-2 rounded-lg bg-brand text-white text-sm font-medium"
          >
            {t("adblock.addFirstRule")}
          </button>
        </div>
      ) : (
        <div className="flex-1 rounded-xl bg-white/5 border border-white/10 p-6 overflow-y-auto">
          <div className="space-y-3">
            {filteredRules.map((rule) => {
              const catInfo = CATEGORY_INFO[rule.category] || { icon: "shield", color: "gray" };
              return (
                <div
                  key={rule.tag}
                  className={`rounded-xl border p-4 transition-all ${
                    rule.enabled
                      ? "bg-emerald-500/5 border-emerald-500/20"
                      : "bg-white/5 border-white/10 opacity-60"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <div className={`p-2 rounded-lg flex-shrink-0 ${rule.enabled ? "bg-emerald-500/20" : "bg-white/10"}`}>
                        <ShieldExclamationIcon className={`h-5 w-5 ${rule.enabled ? "text-emerald-400" : "text-slate-400"}`} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h4 className="font-semibold text-white">{rule.name}</h4>
                          <span className={`px-2 py-0.5 rounded text-xs bg-${catInfo.color}-500/20 text-${catInfo.color}-400`}>
                            {t(`adblock.categories.${rule.category}`)}
                          </span>
                          {rule.region && (
                            <span className="px-2 py-0.5 rounded text-xs bg-white/10 text-slate-400 flex items-center gap-1">
                              <GlobeAltIcon className="h-3 w-3" />
                              {rule.region.toUpperCase()}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-500 mt-0.5">
                          {t(`adblock.descriptions.${rule.tag}`, { defaultValue: rule.description })}
                        </p>
                        <p className="text-xs text-slate-600 mt-1 font-mono truncate">{rule.url}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {/* Toggle Switch */}
                      <button
                        onClick={() => handleToggle(rule.tag)}
                        disabled={actionLoading === `toggle-${rule.tag}`}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          rule.enabled ? "bg-emerald-500" : "bg-slate-600"
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            rule.enabled ? "translate-x-6" : "translate-x-1"
                          }`}
                        />
                      </button>
                      <button
                        onClick={() => handleEdit(rule)}
                        className="p-1.5 rounded-lg text-slate-400 hover:bg-white/10 hover:text-white"
                        title={t("common.edit")}
                      >
                        <PencilIcon className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(rule.tag)}
                        disabled={actionLoading === `delete-${rule.tag}`}
                        className="p-1.5 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                        title={t("common.delete")}
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                  <div className="mt-2 flex items-center gap-4 text-xs text-slate-500">
                    <span>{t("adblock.format")}: {rule.format}</span>
                    <span>{t("adblock.outbound")}: {rule.outbound}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Add Modal */}
      {showAddModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">{t("adblock.addRule")}</h2>
                <button
                  onClick={() => {
                    setShowAddModal(false);
                    resetForm();
                  }}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("adblock.ruleTag")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={formTag}
                  onChange={(e) => setFormTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-"))}
                  placeholder={t("adblock.ruleTagPlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
                <p className="text-xs text-slate-500 mt-1">{t("adblock.ruleTagHint")}</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("adblock.ruleName")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder={t("adblock.ruleNamePlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("adblock.ruleUrl")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="url"
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  placeholder={t("adblock.ruleUrlPlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">{t("common.description")}</label>
                <input
                  type="text"
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  placeholder={t("adblock.descriptionPlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t("adblock.format")}</label>
                  <select
                    value={formFormat}
                    onChange={(e) => setFormFormat(e.target.value as "adblock" | "hosts" | "domains")}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                  >
                    <option value="adblock">Adblock Plus</option>
                    <option value="hosts">Hosts</option>
                    <option value="domains">Domains</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t("adblock.category")}</label>
                  <select
                    value={formCategory}
                    onChange={(e) => setFormCategory(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                  >
                    <option value="general">{t("adblock.categories.general")}</option>
                    <option value="privacy">{t("adblock.categories.privacy")}</option>
                    <option value="regional">{t("adblock.categories.regional")}</option>
                    <option value="security">{t("adblock.categories.security")}</option>
                    <option value="antiadblock">{t("adblock.categories.antiadblock")}</option>
                  </select>
                </div>
              </div>

              {formCategory === "regional" && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t("adblock.region")}</label>
                  <input
                    type="text"
                    value={formRegion}
                    onChange={(e) => setFormRegion(e.target.value.toLowerCase())}
                    placeholder={t("adblock.regionPlaceholder")}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                  <p className="text-xs text-slate-500 mt-1">{t("adblock.regionHint")}</p>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowAddModal(false);
                  resetForm();
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t("common.cancel")}
              </button>
              <button
                onClick={handleCreate}
                disabled={actionLoading === "create" || !formTag || !formName || !formUrl}
                className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {actionLoading === "create" ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : (
                  <PlusIcon className="h-4 w-4" />
                )}
                {t("common.add")}
              </button>
            </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Edit Modal */}
      {showEditModal && editingRule && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">{t("adblock.editRule")}</h2>
                <button
                  onClick={() => {
                    setShowEditModal(false);
                    setEditingRule(null);
                    resetForm();
                  }}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">{t("adblock.ruleTag")}</label>
                <input
                  type="text"
                  value={formTag}
                  disabled
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-500 cursor-not-allowed"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("adblock.ruleName")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("adblock.ruleUrl")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="url"
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">{t("common.description")}</label>
                <input
                  type="text"
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t("adblock.format")}</label>
                  <select
                    value={formFormat}
                    onChange={(e) => setFormFormat(e.target.value as "adblock" | "hosts" | "domains")}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                  >
                    <option value="adblock">Adblock Plus</option>
                    <option value="hosts">Hosts</option>
                    <option value="domains">Domains</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t("adblock.category")}</label>
                  <select
                    value={formCategory}
                    onChange={(e) => setFormCategory(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                  >
                    <option value="general">{t("adblock.categories.general")}</option>
                    <option value="privacy">{t("adblock.categories.privacy")}</option>
                    <option value="regional">{t("adblock.categories.regional")}</option>
                    <option value="security">{t("adblock.categories.security")}</option>
                    <option value="antiadblock">{t("adblock.categories.antiadblock")}</option>
                  </select>
                </div>
              </div>

              {formCategory === "regional" && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t("adblock.region")}</label>
                  <input
                    type="text"
                    value={formRegion}
                    onChange={(e) => setFormRegion(e.target.value.toLowerCase())}
                    placeholder={t("adblock.regionPlaceholder")}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowEditModal(false);
                  setEditingRule(null);
                  resetForm();
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t("common.cancel")}
              </button>
              <button
                onClick={handleUpdate}
                disabled={actionLoading === "update" || !formName || !formUrl}
                className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {actionLoading === "update" ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : (
                  <CheckIcon className="h-4 w-4" />
                )}
                {t("common.save")}
              </button>
            </div>
          </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}
