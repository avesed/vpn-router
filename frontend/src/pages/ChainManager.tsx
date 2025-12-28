import { useState, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import {
  PlusIcon,
  ArrowPathIcon,
  TrashIcon,
  PencilSquareIcon,
  ChevronUpIcon,
  ChevronDownIcon,
  XMarkIcon,
  LinkIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ExclamationTriangleIcon,
  QuestionMarkCircleIcon,
  GlobeAltIcon,
  ComputerDesktopIcon,
  ArrowRightIcon
} from "@heroicons/react/24/outline";
import { api } from "../api/client";
import type {
  NodeChain,
  NodeChainCreateRequest,
  NodeChainUpdateRequest,
  PeerNode,
  ChainHealthStatus
} from "../types";

// Health status color and icon mapping
function getHealthStatusInfo(status: ChainHealthStatus) {
  switch (status) {
    case "healthy":
      return {
        color: "text-emerald-400",
        bgColor: "bg-emerald-500/20",
        borderColor: "border-emerald-500/30",
        icon: CheckCircleIcon
      };
    case "degraded":
      return {
        color: "text-amber-400",
        bgColor: "bg-amber-500/20",
        borderColor: "border-amber-500/30",
        icon: ExclamationTriangleIcon
      };
    case "unhealthy":
      return {
        color: "text-rose-400",
        bgColor: "bg-rose-500/20",
        borderColor: "border-rose-500/30",
        icon: ExclamationCircleIcon
      };
    default:
      return {
        color: "text-slate-400",
        bgColor: "bg-slate-500/20",
        borderColor: "border-slate-500/30",
        icon: QuestionMarkCircleIcon
      };
  }
}

// Format timestamp for display (using i18n)
function formatTimestamp(timestamp: string | undefined, t: (key: string, options?: Record<string, unknown>) => string): string {
  if (!timestamp) return "-";
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return t("common.justNow");
  if (diffMins < 60) return t("common.minutesAgo", { count: diffMins });
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return t("common.hoursAgo", { count: diffHours });
  const diffDays = Math.floor(diffHours / 24);
  return t("common.daysAgo", { count: diffDays });
}

export default function ChainManager() {
  const { t } = useTranslation();
  const [chains, setChains] = useState<NodeChain[]>([]);
  const [peerNodes, setPeerNodes] = useState<PeerNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [editingChain, setEditingChain] = useState<NodeChain | null>(null);
  const [checkingHealth, setCheckingHealth] = useState<string | null>(null);

  // Form state
  const [formData, setFormData] = useState({
    tag: "",
    name: "",
    description: "",
    hops: [] as string[],
    hop_protocols: {} as Record<string, string>,
    entry_rules: "",
    relay_rules: "",
    priority: 100,
    enabled: true
  });

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [chainsRes, nodesRes] = await Promise.all([
        api.getNodeChains(),
        api.getPeerNodes()
      ]);
      setChains(chainsRes.chains || []);
      setPeerNodes(nodesRes.nodes || []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t("common.loadFailed");
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const resetForm = useCallback(() => {
    setFormData({
      tag: "",
      name: "",
      description: "",
      hops: [],
      hop_protocols: {},
      entry_rules: "",
      relay_rules: "",
      priority: 100,
      enabled: true
    });
  }, []);

  // [可访问性] Escape 键关闭模态框
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape" && showModal) {
        setShowModal(false);
        setEditingChain(null);
        resetForm();
      }
    };

    if (showModal) {
      document.addEventListener("keydown", handleEscape);
      return () => document.removeEventListener("keydown", handleEscape);
    }
  }, [showModal, resetForm]);

  const openAddModal = () => {
    resetForm();
    setEditingChain(null);
    setShowModal(true);
  };

  const openEditModal = (chain: NodeChain) => {
    setEditingChain(chain);
    setFormData({
      tag: chain.tag,
      name: chain.name,
      description: chain.description || "",
      hops: chain.hops || [],
      hop_protocols: chain.hop_protocols || {},
      entry_rules: chain.entry_rules ? JSON.stringify(chain.entry_rules, null, 2) : "",
      relay_rules: chain.relay_rules ? JSON.stringify(chain.relay_rules, null, 2) : "",
      priority: chain.priority,
      enabled: chain.enabled
    });
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setEditingChain(null);
    resetForm();
  };

  const validateJson = (str: string): boolean => {
    if (!str.trim()) return true;
    try {
      JSON.parse(str);
      return true;
    } catch {
      return false;
    }
  };

  const handleSubmit = async () => {
    // Validation
    if (!formData.tag.trim() || !formData.name.trim()) {
      setError(t("chains.fillRequiredFields"));
      return;
    }

    if (formData.hops.length < 1) {
      setError(t("chains.minHopsRequired"));
      return;
    }

    if (!validateJson(formData.entry_rules) || !validateJson(formData.relay_rules)) {
      setError(t("chains.invalidJson"));
      return;
    }

    try {
      const payload: NodeChainCreateRequest | NodeChainUpdateRequest = {
        name: formData.name.trim(),
        description: formData.description.trim() || undefined,
        hops: formData.hops,
        hop_protocols: Object.keys(formData.hop_protocols).length > 0 ? formData.hop_protocols : undefined,
        entry_rules: formData.entry_rules.trim() ? JSON.parse(formData.entry_rules) : undefined,
        relay_rules: formData.relay_rules.trim() ? JSON.parse(formData.relay_rules) : undefined,
        priority: formData.priority,
        enabled: formData.enabled
      };

      if (editingChain) {
        await api.updateNodeChain(editingChain.tag, payload);
      } else {
        await api.createNodeChain({
          tag: formData.tag.trim(),
          ...payload
        } as NodeChainCreateRequest);
      }

      closeModal();
      await loadData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : (editingChain ? t("chains.updateFailed") : t("chains.createFailed"));
      setError(message);
    }
  };

  const handleDelete = async (chain: NodeChain) => {
    if (!window.confirm(t("chains.confirmDelete", { name: chain.name }))) {
      return;
    }

    try {
      await api.deleteNodeChain(chain.tag);
      await loadData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t("chains.deleteFailed");
      setError(message);
    }
  };

  const handleHealthCheck = async (chain: NodeChain) => {
    setCheckingHealth(chain.tag);
    try {
      await api.triggerChainHealthCheck(chain.tag);
      await loadData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t("chains.healthCheckFailed");
      setError(message);
    } finally {
      setCheckingHealth(null);
    }
  };

  const addHop = () => {
    setFormData(prev => ({
      ...prev,
      hops: [...prev.hops, ""]
    }));
  };

  const removeHop = (index: number) => {
    setFormData(prev => {
      const newHops = [...prev.hops];
      const removedNode = newHops[index];
      newHops.splice(index, 1);

      // Also remove from hop_protocols
      const newProtocols = { ...prev.hop_protocols };
      if (removedNode) {
        delete newProtocols[removedNode];
      }

      return {
        ...prev,
        hops: newHops,
        hop_protocols: newProtocols
      };
    });
  };

  const moveHop = (index: number, direction: "up" | "down") => {
    const newIndex = direction === "up" ? index - 1 : index + 1;
    if (newIndex < 0 || newIndex >= formData.hops.length) return;

    setFormData(prev => {
      const newHops = [...prev.hops];
      [newHops[index], newHops[newIndex]] = [newHops[newIndex], newHops[index]];
      return {
        ...prev,
        hops: newHops
      };
    });
  };

  const updateHop = (index: number, nodeTag: string) => {
    setFormData(prev => {
      const newHops = [...prev.hops];
      const oldNode = newHops[index];
      newHops[index] = nodeTag;

      // Update hop_protocols
      const newProtocols = { ...prev.hop_protocols };
      if (oldNode) {
        delete newProtocols[oldNode];
      }
      if (nodeTag) {
        const node = peerNodes.find(n => n.tag === nodeTag);
        if (node) {
          newProtocols[nodeTag] = node.tunnel_type || "wireguard";
        }
      }

      return {
        ...prev,
        hops: newHops,
        hop_protocols: newProtocols
      };
    });
  };

  // Get node name by tag
  const getNodeName = (tag: string): string => {
    const node = peerNodes.find(n => n.tag === tag);
    return node?.name || tag;
  };

  // Render chain visualization
  const renderChainVisualization = (chain: NodeChain) => {
    const hops = chain.hops || [];

    return (
      <div className="flex items-center gap-1 flex-wrap">
        {/* Local */}
        <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-brand/20 text-brand text-xs font-medium">
          <ComputerDesktopIcon className="h-3.5 w-3.5" />
          <span>{t("chains.local")}</span>
        </div>

        {hops.map((hop, index) => {
          const protocol = chain.hop_protocols?.[hop] || "wireguard";
          return (
            <div key={index} className="flex items-center gap-1">
              <ArrowRightIcon className="h-3.5 w-3.5 text-slate-500" />
              <div className="flex flex-col items-center gap-0.5">
                <div className="px-2 py-1 rounded-lg bg-blue-500/20 text-blue-400 text-xs font-medium">
                  {getNodeName(hop)}
                </div>
                <span className="text-[10px] text-slate-500 uppercase">{protocol}</span>
              </div>
            </div>
          );
        })}

        {/* Internet */}
        <ArrowRightIcon className="h-3.5 w-3.5 text-slate-500" />
        <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-emerald-500/20 text-emerald-400 text-xs font-medium">
          <GlobeAltIcon className="h-3.5 w-3.5" />
          <span>{t("chains.internet")}</span>
        </div>
      </div>
    );
  };

  return (
    <div>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white">{t("chains.title")}</h2>
          <p className="text-slate-400 text-sm mt-1">{t("chains.subtitle")}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 text-slate-300 hover:bg-white/10 transition-colors disabled:opacity-50"
          >
            <ArrowPathIcon className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            <span className="hidden md:inline">{t("chains.refresh")}</span>
          </button>
          <button
            onClick={openAddModal}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-brand to-blue-600 text-white font-medium shadow-lg shadow-brand/25 hover:shadow-brand/40 transition-shadow"
          >
            <PlusIcon className="h-4 w-4" />
            <span>{t("chains.addChain")}</span>
          </button>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="mb-4 p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
          {error}
          <button onClick={() => setError(null)} className="ml-2 underline">
            {t("common.close")}
          </button>
        </div>
      )}

      {/* Loading state */}
      {loading && chains.length === 0 && (
        <div className="flex items-center justify-center py-12">
          <ArrowPathIcon className="h-8 w-8 text-slate-400 animate-spin" />
        </div>
      )}

      {/* Empty state */}
      {!loading && chains.length === 0 && (
        <div className="text-center py-12">
          <LinkIcon className="h-12 w-12 text-slate-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300 mb-2">
            {t("chains.noChains")}
          </h3>
          <p className="text-slate-500 text-sm mb-6">
            {t("chains.noChainsHint")}
          </p>
          <button
            onClick={openAddModal}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-brand text-white font-medium"
          >
            <PlusIcon className="h-4 w-4" />
            {t("chains.addChain")}
          </button>
        </div>
      )}

      {/* Chain list */}
      {chains.length > 0 && (
        <div className="grid gap-4">
          {chains.map(chain => {
            const healthInfo = getHealthStatusInfo(chain.health_status);
            const HealthIcon = healthInfo.icon;

            return (
              <div
                key={chain.tag}
                className={`rounded-2xl border ${healthInfo.borderColor} bg-slate-800/50 p-4 md:p-6`}
              >
                {/* Header row */}
                <div className="flex items-start justify-between gap-4 mb-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <h3 className="text-lg font-semibold text-white truncate">
                        {chain.name}
                      </h3>
                      {/* Enabled/Disabled badge */}
                      <span
                        className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                          chain.enabled
                            ? "bg-emerald-500/20 text-emerald-400"
                            : "bg-slate-500/20 text-slate-400"
                        }`}
                      >
                        {chain.enabled ? t("chains.enabled") : t("chains.disabled")}
                      </span>
                      {/* Hop count badge */}
                      <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400">
                        {t("chains.hopCount", { count: chain.hops?.length || 0 })}
                      </span>
                    </div>
                    <p className="text-sm text-slate-400 truncate">
                      {chain.description || chain.tag}
                    </p>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleHealthCheck(chain)}
                      disabled={checkingHealth === chain.tag}
                      className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 transition-colors disabled:opacity-50"
                      title={t("chains.checkHealth")}
                    >
                      <ArrowPathIcon
                        className={`h-4 w-4 ${checkingHealth === chain.tag ? "animate-spin" : ""}`}
                      />
                    </button>
                    <button
                      onClick={() => openEditModal(chain)}
                      className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
                      title={t("common.edit")}
                    >
                      <PencilSquareIcon className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => handleDelete(chain)}
                      className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                      title={t("common.delete")}
                    >
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                {/* Chain visualization */}
                <div className="mb-4">
                  {renderChainVisualization(chain)}
                </div>

                {/* Footer info */}
                <div className="flex flex-wrap items-center gap-4 text-sm">
                  {/* Health status */}
                  <div className={`flex items-center gap-1.5 ${healthInfo.color}`}>
                    <HealthIcon className="h-4 w-4" />
                    <span>{t(`chains.status.${chain.health_status}`)}</span>
                  </div>

                  {/* Last health check */}
                  {chain.last_health_check && (
                    <div className="text-slate-500">
                      {t("chains.lastHealthCheck")}: {formatTimestamp(chain.last_health_check, t)}
                    </div>
                  )}

                  {/* Priority */}
                  <div className="text-slate-500">
                    {t("chains.priority")}: {chain.priority}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Add/Edit Modal */}
      {showModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="chain-modal-title"
              className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-2xl"
            >
              {/* Modal header */}
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h3 id="chain-modal-title" className="text-xl font-bold text-white">
                    {editingChain ? t("chains.editChain") : t("chains.addChain")}
                  </h3>
                  <button
                    onClick={closeModal}
                    className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>

              {/* Modal body */}
              <div className="p-6 space-y-4 max-h-[60vh] overflow-y-auto">
              {/* Tag (only for new) */}
              {!editingChain && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("chains.tag")} <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    value={formData.tag}
                    onChange={e => setFormData(prev => ({ ...prev, tag: e.target.value }))}
                    placeholder={t("chains.tagPlaceholder")}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                  <p className="mt-1 text-xs text-slate-500">{t("chains.tagHint")}</p>
                </div>
              )}

              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("chains.name")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={e => setFormData(prev => ({ ...prev, name: e.target.value }))}
                  placeholder={t("chains.namePlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("chains.description")}
                </label>
                <input
                  type="text"
                  value={formData.description}
                  onChange={e => setFormData(prev => ({ ...prev, description: e.target.value }))}
                  placeholder={t("chains.descriptionPlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              {/* Hops */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("chains.hops")} <span className="text-red-400">*</span>
                </label>
                <p className="text-xs text-slate-500 mb-3">{t("chains.hopsHint")}</p>

                {peerNodes.length === 0 ? (
                  <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 text-sm">
                    {t("chains.noNodes")}
                    <p className="text-amber-400/60 mt-1">{t("chains.noNodesHint")}</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {formData.hops.map((hop, index) => (
                      <div key={index} className="flex items-center gap-2">
                        {/* Hop number */}
                        <span className="w-16 text-xs text-slate-500 text-center">
                          {t("chains.hopNumber", { number: index + 1 })}
                        </span>

                        {/* Node selector */}
                        <select
                          value={hop}
                          onChange={e => updateHop(index, e.target.value)}
                          className="flex-1 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                        >
                          <option value="">{t("chains.selectNode")}</option>
                          {peerNodes.map(node => (
                            <option key={node.tag} value={node.tag}>
                              {node.name} ({node.tunnel_type || "wireguard"})
                            </option>
                          ))}
                        </select>

                        {/* Move buttons */}
                        <button
                          onClick={() => moveHop(index, "up")}
                          disabled={index === 0}
                          className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                          title={t("chains.moveUp")}
                        >
                          <ChevronUpIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => moveHop(index, "down")}
                          disabled={index === formData.hops.length - 1}
                          className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                          title={t("chains.moveDown")}
                        >
                          <ChevronDownIcon className="h-4 w-4" />
                        </button>

                        {/* Remove button */}
                        <button
                          onClick={() => removeHop(index)}
                          className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                          title={t("chains.removeHop")}
                        >
                          <XMarkIcon className="h-4 w-4" />
                        </button>
                      </div>
                    ))}

                    {/* Add hop button */}
                    <button
                      onClick={addHop}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 text-slate-300 hover:bg-white/10 transition-colors w-full justify-center"
                    >
                      <PlusIcon className="h-4 w-4" />
                      {t("chains.addHop")}
                    </button>
                  </div>
                )}
              </div>

              {/* Priority */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("chains.priority")}
                </label>
                <input
                  type="number"
                  value={formData.priority}
                  onChange={e => setFormData(prev => ({ ...prev, priority: parseInt(e.target.value) || 0 }))}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                />
                <p className="mt-1 text-xs text-slate-500">{t("chains.priorityHint")}</p>
              </div>

              {/* Entry Rules (JSON) */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("chains.entryRules")}
                </label>
                <textarea
                  value={formData.entry_rules}
                  onChange={e => setFormData(prev => ({ ...prev, entry_rules: e.target.value }))}
                  placeholder={t("chains.entryRulesPlaceholder")}
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-sm"
                />
                <p className="mt-1 text-xs text-slate-500">{t("chains.entryRulesHint")}</p>
              </div>

              {/* Relay Rules (JSON) */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("chains.relayRules")}
                </label>
                <textarea
                  value={formData.relay_rules}
                  onChange={e => setFormData(prev => ({ ...prev, relay_rules: e.target.value }))}
                  placeholder="{}"
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-sm"
                />
                <p className="mt-1 text-xs text-slate-500">{t("chains.relayRulesHint")}</p>
              </div>

              {/* Enabled toggle */}
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-slate-400">
                  {t("chains.enabled")}
                </label>
                <button
                  onClick={() => setFormData(prev => ({ ...prev, enabled: !prev.enabled }))}
                  className={`relative w-12 h-6 rounded-full transition-colors ${
                    formData.enabled ? "bg-brand" : "bg-slate-600"
                  }`}
                >
                  <span
                    className={`absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform ${
                      formData.enabled ? "translate-x-6" : ""
                    }`}
                  />
                </button>
              </div>
              </div>

              {/* Modal footer */}
              <div className="p-6 border-t border-white/10 flex justify-end gap-3">
                <button
                  onClick={closeModal}
                  className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
                >
                  {t("common.cancel")}
                </button>
                <button
                  onClick={handleSubmit}
                  className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors"
                >
                  {editingChain ? t("common.save") : t("common.create")}
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
