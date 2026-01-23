import { useState, useEffect, useCallback, useRef } from "react";
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
  ArrowRightIcon,
  PlayIcon,
  StopIcon,
  SignalIcon,
  SignalSlashIcon
} from "@heroicons/react/24/outline";
import { api } from "../api/client";
import { ConfirmDialog } from "../components/ConfirmDialog";
import type {
  NodeChain,
  NodeChainCreateRequest,
  NodeChainUpdateRequest,
  PeerNode,
  ChainHealthStatus,
  ChainHealthCheckResponse,
  ChainHopResult,
  DownstreamStatus,
  ChainState,
  ChainMarkType
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

// Hop status color and icon mapping
function getHopStatusInfo(status: ChainHopResult["status"]) {
  switch (status) {
    case "connected":
      return {
        color: "text-emerald-400",
        bgColor: "bg-emerald-500/20",
        icon: CheckCircleIcon
      };
    case "connecting":
      return {
        color: "text-amber-400",
        bgColor: "bg-amber-500/20",
        icon: ArrowPathIcon
      };
    case "disconnected":
      return {
        color: "text-slate-400",
        bgColor: "bg-slate-500/20",
        icon: ExclamationCircleIcon
      };
    case "error":
    case "unreachable":
      return {
        color: "text-rose-400",
        bgColor: "bg-rose-500/20",
        icon: ExclamationCircleIcon
      };
    case "not_found":
      return {
        color: "text-orange-400",
        bgColor: "bg-orange-500/20",
        icon: QuestionMarkCircleIcon
      };
    default:
      return {
        color: "text-slate-400",
        bgColor: "bg-slate-500/20",
        icon: QuestionMarkCircleIcon
      };
  }
}

// Downstream status color and icon mapping
function getDownstreamStatusInfo(status: DownstreamStatus | undefined) {
  switch (status) {
    case "connected":
      return {
        color: "text-emerald-400",
        bgColor: "bg-emerald-500/20",
        borderColor: "border-emerald-500/30",
        icon: CheckCircleIcon
      };
    case "disconnected":
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

// Chain state color and icon mapping
function getChainStateInfo(state: ChainState | undefined) {
  switch (state) {
    case "active":
      return {
        color: "text-emerald-400",
        bgColor: "bg-emerald-500/20",
        borderColor: "border-emerald-500/30",
        icon: SignalIcon,
        pulseClass: ""
      };
    case "activating":
      return {
        color: "text-amber-400",
        bgColor: "bg-amber-500/20",
        borderColor: "border-amber-500/30",
        icon: ArrowPathIcon,
        pulseClass: "animate-spin"
      };
    case "error":
      return {
        color: "text-rose-400",
        bgColor: "bg-rose-500/20",
        borderColor: "border-rose-500/30",
        icon: ExclamationCircleIcon,
        pulseClass: ""
      };
    case "inactive":
    default:
      return {
        color: "text-slate-400",
        bgColor: "bg-slate-500/20",
        borderColor: "border-slate-500/30",
        icon: SignalSlashIcon,
        pulseClass: ""
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
  const [healthCheckResult, setHealthCheckResult] = useState<ChainHealthCheckResponse | null>(null);
  const [showHealthModal, setShowHealthModal] = useState(false);
  const [saving, setSaving] = useState(false);

  // Delete confirmation state
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [chainToDelete, setChainToDelete] = useState<NodeChain | null>(null);

  // Activation state
  const [activatingChain, setActivatingChain] = useState<string | null>(null);

  // Terminal egress state (with cache support)
  const [terminalEgressList, setTerminalEgressList] = useState<Array<{ tag: string; type: string; description?: string; enabled: boolean }>>([]);
  const [loadingEgress, setLoadingEgress] = useState(false);
  const [egressCached, setEgressCached] = useState<boolean>(false);
  const [egressCachedAt, setEgressCachedAt] = useState<string | null>(null);
  const egressRequestRef = useRef<string | null>(null);  // Track current egress request to prevent race conditions

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
    enabled: true,
    // Multi-hop chain architecture v2 fields
    exit_egress: "",
    chain_mark_type: "dscp" as ChainMarkType
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

  // Auto-refresh every 30 seconds to update downstream status
  useEffect(() => {
    const interval = setInterval(() => {
      // Only refresh if not showing modals (to avoid interrupting user)
      if (!showModal && !showHealthModal) {
        loadData();
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [loadData, showModal, showHealthModal]);

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
      enabled: true,
      exit_egress: "",
      chain_mark_type: "dscp" as ChainMarkType
    });
    setTerminalEgressList([]);
  }, []);

  // [可访问性] Escape 键关闭模态框
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        // Close health check modal first (if open)
        if (showHealthModal) {
          setShowHealthModal(false);
          setHealthCheckResult(null);
          return;
        }
        // Then close add/edit modal
        if (showModal) {
          setShowModal(false);
          setEditingChain(null);
          resetForm();
        }
      }
    };

    if (showModal || showHealthModal) {
      document.addEventListener("keydown", handleEscape);
      return () => document.removeEventListener("keydown", handleEscape);
    }
  }, [showModal, showHealthModal, resetForm]);

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
      enabled: chain.enabled,
      exit_egress: chain.exit_egress || "",
      chain_mark_type: chain.chain_mark_type || "dscp"
    });
    setTerminalEgressList([]);
    setShowModal(true);
    // Auto-load terminal egress for edit mode
    if (chain.tag) {
      loadTerminalEgress(chain.tag);
    }
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

    setSaving(true);
    try {
      const payload: NodeChainCreateRequest | NodeChainUpdateRequest = {
        name: formData.name.trim(),
        description: formData.description.trim() || undefined,
        hops: formData.hops,
        hop_protocols: Object.keys(formData.hop_protocols).length > 0 ? formData.hop_protocols : undefined,
        entry_rules: formData.entry_rules.trim() ? JSON.parse(formData.entry_rules) : undefined,
        relay_rules: formData.relay_rules.trim() ? JSON.parse(formData.relay_rules) : undefined,
        priority: formData.priority,
        enabled: formData.enabled,
        // Multi-hop chain architecture v2 fields
        exit_egress: formData.exit_egress.trim() || undefined,
        chain_mark_type: formData.chain_mark_type
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
    } finally {
      setSaving(false);
    }
  };

  // Delete chain - step 1: open confirmation dialog
  const handleDelete = (chain: NodeChain) => {
    setChainToDelete(chain);
    setDeleteConfirmOpen(true);
  };

  // Delete chain - step 2: perform actual deletion after confirmation
  const confirmDeleteChain = useCallback(async () => {
    if (!chainToDelete) return;

    const chain = chainToDelete;
    setDeleteConfirmOpen(false);
    setChainToDelete(null);

    try {
      await api.deleteNodeChain(chain.tag);
      await loadData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t("chains.deleteFailed");
      setError(message);
    }
  }, [chainToDelete, loadData, t]);

  // Cancel delete
  const cancelDeleteChain = useCallback(() => {
    setDeleteConfirmOpen(false);
    setChainToDelete(null);
  }, []);

  const handleHealthCheck = async (chain: NodeChain) => {
    setCheckingHealth(chain.tag);
    try {
      const result = await api.triggerChainHealthCheck(chain.tag);
      setHealthCheckResult(result);
      setShowHealthModal(true);
      await loadData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t("chains.healthCheckFailed");
      setError(message);
    } finally {
      setCheckingHealth(null);
    }
  };

  const closeHealthModal = () => {
    setShowHealthModal(false);
    setHealthCheckResult(null);
  };

  // Activate chain
  const handleActivate = async (chain: NodeChain) => {
    setActivatingChain(chain.tag);
    try {
      await api.activateChain(chain.tag);
      await loadData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t("chains.activateFailed");
      setError(message);
    } finally {
      setActivatingChain(null);
    }
  };

  // Deactivate chain
  const handleDeactivate = async (chain: NodeChain) => {
    setActivatingChain(chain.tag);
    try {
      await api.deactivateChain(chain.tag);
      await loadData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t("chains.deactivateFailed");
      setError(message);
    } finally {
      setActivatingChain(null);
    }
  };

  // Load terminal egress list for a chain (with cache support)
  const loadTerminalEgress = async (chainTag: string, forceRefresh: boolean = false) => {
    // Track current request to prevent race conditions when switching chains quickly
    egressRequestRef.current = chainTag;
    setLoadingEgress(true);
    try {
      const result = await api.getTerminalEgress(chainTag, forceRefresh);
      // Only update state if this is still the current request
      if (egressRequestRef.current === chainTag) {
        setTerminalEgressList(result.egress_list || []);
        setEgressCached(result.cached || false);
        setEgressCachedAt(result.cached_at || null);
      }
    } catch (err: unknown) {
      // Only show error if this is still the current request
      if (egressRequestRef.current === chainTag) {
        const message = err instanceof Error ? err.message : t("chains.loadEgressFailed");
        setError(message);
        setEgressCached(false);
        setEgressCachedAt(null);
      }
    } finally {
      if (egressRequestRef.current === chainTag) {
        setLoadingEgress(false);
      }
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
            const downstreamInfo = getDownstreamStatusInfo(chain.downstream_status);
            const DownstreamIcon = downstreamInfo.icon;
            const stateInfo = getChainStateInfo(chain.chain_state);
            const StateIcon = stateInfo.icon;

            return (
              <div
                key={chain.tag}
                className={`rounded-2xl border ${healthInfo.borderColor} bg-slate-800/50 p-4 md:p-6`}
              >
                {/* Header row */}
                <div className="flex items-start justify-between gap-4 mb-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1 flex-wrap">
                      <h3 className="text-lg font-semibold text-white truncate">
                        {chain.name}
                      </h3>
                      {/* Chain state badge */}
                      <span
                        className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${stateInfo.bgColor} ${stateInfo.color}`}
                      >
                        <StateIcon className={`h-3 w-3 ${stateInfo.pulseClass}`} />
                        {t(`chains.state.${chain.chain_state || "inactive"}`)}
                      </span>
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
                      {/* DSCP value badge (only for DSCP chains with value) */}
                      {chain.chain_mark_type === "dscp" && chain.dscp_value && (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-purple-500/20 text-purple-400">
                          DSCP: {chain.dscp_value}
                        </span>
                      )}
                      {/* Downstream status warning badge (only show when disconnected) */}
                      {chain.downstream_status === "disconnected" && (
                        <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-rose-500/20 text-rose-400">
                          <ExclamationCircleIcon className="h-3 w-3" />
                          {t("chains.downstreamDisconnected")}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-slate-400 truncate">
                      {chain.description || chain.tag}
                      {chain.exit_egress && (
                        <span className="ml-2 text-slate-500">
                          → {chain.exit_egress}
                        </span>
                      )}
                    </p>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2">
                    {/* Activate/Deactivate button */}
                    {chain.chain_state === "active" ? (
                      <button
                        onClick={() => handleDeactivate(chain)}
                        disabled={activatingChain === chain.tag}
                        className="p-2 rounded-lg bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 transition-colors disabled:opacity-50"
                        title={t("chains.deactivate")}
                      >
                        {activatingChain === chain.tag ? (
                          <ArrowPathIcon className="h-4 w-4 animate-spin" />
                        ) : (
                          <StopIcon className="h-4 w-4" />
                        )}
                      </button>
                    ) : (
                      <button
                        onClick={() => handleActivate(chain)}
                        disabled={activatingChain === chain.tag || chain.chain_state === "activating" || !chain.enabled}
                        className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
                        title={t("chains.activate")}
                      >
                        {activatingChain === chain.tag || chain.chain_state === "activating" ? (
                          <ArrowPathIcon className="h-4 w-4 animate-spin" />
                        ) : (
                          <PlayIcon className="h-4 w-4" />
                        )}
                      </button>
                    )}
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

                  {/* Downstream status (only show when not unknown) */}
                  {chain.downstream_status && chain.downstream_status !== "unknown" && (
                    <div className={`flex items-center gap-1.5 ${downstreamInfo.color}`}>
                      <DownstreamIcon className="h-4 w-4" />
                      <span>
                        {t("chains.downstream")}: {t(`chains.downstreamStatus.${chain.downstream_status}`)}
                        {chain.downstream_status === "disconnected" && chain.disconnected_node && (
                          <span className="text-slate-500 ml-1">
                            ({getNodeName(chain.disconnected_node)})
                          </span>
                        )}
                      </span>
                    </div>
                  )}

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

              {/* Chain Mark Type (DSCP vs Xray Email) */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("chains.markType")}
                </label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="chain_mark_type"
                      value="dscp"
                      checked={formData.chain_mark_type === "dscp"}
                      onChange={e => setFormData(prev => ({ ...prev, chain_mark_type: e.target.value as ChainMarkType }))}
                      className="w-4 h-4 text-brand"
                    />
                    <span className="text-white text-sm">DSCP</span>
                    <span className="text-slate-500 text-xs">{t("chains.dscpHint")}</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="chain_mark_type"
                      value="xray_email"
                      checked={formData.chain_mark_type === "xray_email"}
                      onChange={e => setFormData(prev => ({ ...prev, chain_mark_type: e.target.value as ChainMarkType }))}
                      className="w-4 h-4 text-brand"
                    />
                    <span className="text-white text-sm">Xray Email</span>
                    <span className="text-slate-500 text-xs">{t("chains.xrayEmailHint")}</span>
                  </label>
                </div>
              </div>

              {/* Exit Egress (for editing existing chains) - with cache indicator */}
              {editingChain && formData.hops.length > 0 && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("chains.exitEgress")}
                  </label>
                  <div className="flex gap-2">
                    <select
                      value={formData.exit_egress}
                      onChange={e => setFormData(prev => ({ ...prev, exit_egress: e.target.value }))}
                      className="flex-1 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                    >
                      <option value="">{t("chains.selectEgress")}</option>
                      {terminalEgressList.map(egress => (
                        <option key={egress.tag} value={egress.tag} disabled={!egress.enabled}>
                          {egress.description || egress.tag} ({egress.type})
                          {!egress.enabled && ` - ${t("chains.disabled")}`}
                        </option>
                      ))}
                    </select>
                    {/* Cache indicator */}
                    {egressCached && (
                      <span
                        className="px-2 py-2 rounded-lg bg-green-500/10 text-green-400 text-xs flex items-center"
                        title={egressCachedAt ? `${t("chains.cachedAt")}: ${new Date(egressCachedAt).toLocaleString()}` : t("chains.cached")}
                      >
                        {t("chains.cached")}
                      </span>
                    )}
                    <button
                      onClick={() => loadTerminalEgress(editingChain.tag, true)}
                      disabled={loadingEgress}
                      className="px-3 py-2 rounded-lg bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 transition-colors disabled:opacity-50"
                      title={t("chains.refreshEgress")}
                    >
                      <ArrowPathIcon className={`h-4 w-4 ${loadingEgress ? "animate-spin" : ""}`} />
                    </button>
                  </div>
                  <p className="mt-1 text-xs text-slate-500">{t("chains.exitEgressHint")}</p>
                </div>
              )}

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
                  disabled={saving}
                  className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {saving && (
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                  )}
                  {editingChain ? t("common.save") : t("common.create")}
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Health Check Result Modal */}
      {showHealthModal && healthCheckResult && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="health-modal-title"
              className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg"
            >
              {/* Modal header */}
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h3 id="health-modal-title" className="text-xl font-bold text-white">
                    {t("chains.healthCheckResult")}
                  </h3>
                  <button
                    onClick={closeHealthModal}
                    className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>

              {/* Modal body */}
              <div className="p-6 space-y-4">
                {/* Overall status */}
                <div className={`p-4 rounded-xl ${healthCheckResult.healthy ? "bg-emerald-500/10 border border-emerald-500/20" : "bg-rose-500/10 border border-rose-500/20"}`}>
                  <div className="flex items-center gap-3">
                    {healthCheckResult.healthy ? (
                      <CheckCircleIcon className="h-6 w-6 text-emerald-400" />
                    ) : (
                      <ExclamationCircleIcon className="h-6 w-6 text-rose-400" />
                    )}
                    <div>
                      <div className={`font-semibold ${healthCheckResult.healthy ? "text-emerald-400" : "text-rose-400"}`}>
                        {healthCheckResult.healthy ? t("chains.chainHealthy") : t("chains.chainUnhealthy")}
                      </div>
                      <div className="text-sm text-slate-400 mt-1">
                        {healthCheckResult.message}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Per-hop status */}
                <div>
                  <h4 className="text-sm font-medium text-slate-400 mb-3">
                    {t("chains.hopStatus")} ({healthCheckResult.total_hops} {t("chains.hopsTotal")})
                  </h4>
                  <div className="space-y-2">
                    {healthCheckResult.hops.map((hop, index) => {
                      const hopInfo = getHopStatusInfo(hop.status);
                      const HopIcon = hopInfo.icon;
                      return (
                        <div
                          key={index}
                          className={`flex items-center gap-3 p-3 rounded-lg ${hopInfo.bgColor}`}
                        >
                          <div className="flex items-center gap-2 flex-shrink-0">
                            <span className="text-xs text-slate-500 w-12">
                              {t("chains.hopNumber", { number: hop.hop })}
                            </span>
                            <HopIcon className={`h-4 w-4 ${hopInfo.color} ${hop.status === "connecting" ? "animate-spin" : ""}`} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-white font-medium truncate">
                                {getNodeName(hop.node)}
                              </span>
                              {hop.tunnel_type && (
                                <span className="text-xs text-slate-500 uppercase">
                                  {hop.tunnel_type}
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className={`text-xs ${hopInfo.color}`}>
                                {t(`chains.hopStatus.${hop.status}`)}
                              </span>
                              {hop.message && (
                                <span className="text-xs text-slate-500 truncate">
                                  - {hop.message}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Modal footer */}
              <div className="p-6 border-t border-white/10 flex justify-end">
                <button
                  onClick={closeHealthModal}
                  className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors"
                >
                  {t("common.close")}
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={deleteConfirmOpen}
        title={t("chains.confirmDeleteTitle")}
        message={
          chainToDelete ? (
            <span>
              {t("chains.confirmDeleteMessage", { name: chainToDelete.name })}
              <br />
              <span className="text-slate-400 text-xs mt-1 block">
                Tag: <code className="font-mono">{chainToDelete.tag}</code>
              </span>
            </span>
          ) : null
        }
        confirmText={t("common.delete")}
        variant="danger"
        onConfirm={confirmDeleteChain}
        onCancel={cancelDeleteChain}
      />
    </div>
  );
}
