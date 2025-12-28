import { useState, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import {
  PlusIcon,
  ArrowPathIcon,
  TrashIcon,
  PencilIcon,
  LinkIcon,
  XMarkIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ClockIcon,
  SignalIcon,
  SignalSlashIcon,
  ServerStackIcon,
  CheckIcon,
  KeyIcon,
  EyeIcon,
  EyeSlashIcon
} from "@heroicons/react/24/outline";
import { api } from "../api/client";
import { ConfirmDialog } from "../components/ConfirmDialog";
import type {
  PeerNode,
  PeerNodeCreateRequest,
  PeerNodeUpdateRequest,
  PeerTunnelType,
  PeerXrayProtocol,
  PeerTunnelStatus
} from "../types";

// Status color mapping
const statusColors: Record<PeerTunnelStatus, string> = {
  connected: "text-green-400",
  connecting: "text-yellow-400",
  disconnected: "text-slate-400",
  error: "text-red-400"
};

const statusBgColors: Record<PeerTunnelStatus, string> = {
  connected: "bg-green-500/20",
  connecting: "bg-yellow-500/20",
  disconnected: "bg-slate-500/20",
  error: "bg-red-500/20"
};

export default function PeerManager() {
  const { t } = useTranslation();
  const [nodes, setNodes] = useState<PeerNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [editingNode, setEditingNode] = useState<PeerNode | null>(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [detailNode, setDetailNode] = useState<PeerNode | null>(null);
  const [selectedNodes, setSelectedNodes] = useState<Set<string>>(new Set());
  const [connectingNodes, setConnectingNodes] = useState<Set<string>>(new Set());
  const [disconnectingNodes, setDisconnectingNodes] = useState<Set<string>>(new Set());
  const [batchConnecting, setBatchConnecting] = useState(false);
  const [batchDisconnecting, setBatchDisconnecting] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Form state
  const [formData, setFormData] = useState<{
    tag: string;
    name: string;
    description: string;
    endpoint: string;
    psk: string;
    tunnel_type: PeerTunnelType;
    xray_protocol: PeerXrayProtocol;
    tls_verify: boolean;
    tls_fingerprint: string;
    auto_reconnect: boolean;
  }>({
    tag: "",
    name: "",
    description: "",
    endpoint: "",
    psk: "",
    tunnel_type: "wireguard",
    xray_protocol: "vless",
    tls_verify: true,
    tls_fingerprint: "",
    auto_reconnect: true
  });
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  // [CR-006] PSK visibility toggle for security (prevent shoulder surfing)
  const [showPsk, setShowPsk] = useState(false);

  // [CR-009] Custom delete confirmation dialog state
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [nodeToDelete, setNodeToDelete] = useState<PeerNode | null>(null);

  // Auto-refresh interval ref
  const refreshIntervalRef = useRef<number | null>(null);
  // Success message timeout ref
  const successTimeoutRef = useRef<number | null>(null);

  // Load peer nodes
  const loadNodes = useCallback(async () => {
    try {
      const response = await api.getPeerNodes();
      setNodes(response.nodes || []);
      setError(null);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load and auto-refresh setup
  useEffect(() => {
    loadNodes();

    // Set up auto-refresh every 10 seconds
    refreshIntervalRef.current = window.setInterval(() => {
      loadNodes();
    }, 10000);

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
      if (successTimeoutRef.current) {
        clearTimeout(successTimeoutRef.current);
      }
    };
  }, [loadNodes]);

  // [可访问性] Escape 键关闭模态框
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (showModal) {
          setShowModal(false);
          resetForm();
        } else if (showDetailModal) {
          setShowDetailModal(false);
          setDetailNode(null);
        }
      }
    };

    if (showModal || showDetailModal) {
      document.addEventListener("keydown", handleEscape);
      return () => document.removeEventListener("keydown", handleEscape);
    }
  }, [showModal, showDetailModal]);

  // Show success message with auto-hide (memoized for dependency stability)
  const showSuccess = useCallback((message: string) => {
    // Clear any existing timeout to prevent race conditions
    if (successTimeoutRef.current) {
      clearTimeout(successTimeoutRef.current);
    }
    setSuccessMessage(message);
    successTimeoutRef.current = window.setTimeout(() => setSuccessMessage(null), 3000);
  }, []);

  // Handle form input change
  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value, type } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? (e.target as HTMLInputElement).checked : value
    }));
  };

  // Reset form
  const resetForm = () => {
    setFormData({
      tag: "",
      name: "",
      description: "",
      endpoint: "",
      psk: "",
      tunnel_type: "wireguard",
      xray_protocol: "vless",
      tls_verify: true,
      tls_fingerprint: "",
      auto_reconnect: true
    });
    setFormError(null);
    setEditingNode(null);
    setShowPsk(false);  // [CR-006] Reset PSK visibility on form reset
  };

  // Open add modal
  const handleAddNode = () => {
    resetForm();
    setShowModal(true);
  };

  // Open edit modal
  const handleEditNode = (node: PeerNode) => {
    setEditingNode(node);
    setFormData({
      tag: node.tag,
      name: node.name,
      description: node.description || "",
      endpoint: node.endpoint,
      psk: "",
      tunnel_type: node.tunnel_type,
      xray_protocol: node.xray_protocol || "vless",
      tls_verify: node.tls_verify !== 0,  // Convert 0/1 to boolean
      tls_fingerprint: node.tls_fingerprint || "",
      auto_reconnect: node.auto_reconnect
    });
    setShowModal(true);
  };

  // Close modal
  const handleCloseModal = () => {
    setShowModal(false);
    resetForm();
  };

  // Submit form
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    // Validation
    if (!formData.tag || !formData.name || !formData.endpoint) {
      setFormError(t("peers.fillRequiredFields"));
      return;
    }

    // [安全] PSK 验证：新建时必填，编辑时如有提供则验证长度
    if (!editingNode && formData.psk.length < 16) {
      setFormError(t("peers.pskTooShort"));
      return;
    }
    if (editingNode && formData.psk && formData.psk.length < 16) {
      setFormError(t("peers.pskTooShort"));
      return;
    }

    setSaving(true);
    try {
      if (editingNode) {
        // Update existing node
        const updateData: PeerNodeUpdateRequest = {
          name: formData.name,
          description: formData.description || undefined,
          endpoint: formData.endpoint,
          auto_reconnect: formData.auto_reconnect,
          // TLS 配置（用于 Trojan 协议）
          tls_verify: formData.tls_verify,
          tls_fingerprint: formData.tls_fingerprint || undefined
        };
        if (formData.psk) {
          updateData.psk = formData.psk;
        }
        await api.updatePeerNode(editingNode.tag, updateData);
        showSuccess(t("peers.updateSuccess", { name: formData.name }));
      } else {
        // Create new node
        const createData: PeerNodeCreateRequest = {
          tag: formData.tag,
          name: formData.name,
          description: formData.description || undefined,
          endpoint: formData.endpoint,
          psk: formData.psk,
          tunnel_type: formData.tunnel_type,
          xray_protocol: formData.tunnel_type === "xray" ? formData.xray_protocol : undefined,
          // TLS 配置（用于 Trojan 协议）
          tls_verify: formData.tls_verify,
          tls_fingerprint: formData.tls_fingerprint || undefined,
          auto_reconnect: formData.auto_reconnect
        };
        await api.createPeerNode(createData);
        showSuccess(t("peers.createSuccess", { name: formData.name }));
      }
      handleCloseModal();
      loadNodes();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setFormError(errorMessage);
    } finally {
      setSaving(false);
    }
  };

  // [CR-009] Delete node - step 1: open confirmation dialog
  const handleDeleteNode = (node: PeerNode) => {
    setNodeToDelete(node);
    setDeleteConfirmOpen(true);
  };

  // [CR-009] Delete node - step 2: perform actual deletion after confirmation
  // Memoized to prevent unnecessary re-renders of ConfirmDialog
  const confirmDeleteNode = useCallback(async () => {
    if (!nodeToDelete) return;

    const node = nodeToDelete;
    setDeleteConfirmOpen(false);
    setNodeToDelete(null);

    try {
      await api.deletePeerNode(node.tag);
      showSuccess(t("peers.deleteSuccess", { name: node.name }));
      loadNodes();
      setSelectedNodes((prev) => {
        const next = new Set(prev);
        next.delete(node.tag);
        return next;
      });
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setError(errorMessage);
    }
  }, [nodeToDelete, loadNodes, showSuccess, t]);

  // [CR-009] Cancel delete - memoized to prevent unnecessary re-renders
  const cancelDeleteNode = useCallback(() => {
    setDeleteConfirmOpen(false);
    setNodeToDelete(null);
  }, []);

  // Connect node
  const handleConnectNode = async (node: PeerNode) => {
    setConnectingNodes((prev) => new Set(prev).add(node.tag));
    try {
      await api.connectPeerNode(node.tag);
      showSuccess(t("peers.connectSuccess", { name: node.name }));
      loadNodes();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setError(errorMessage);
    } finally {
      setConnectingNodes((prev) => {
        const next = new Set(prev);
        next.delete(node.tag);
        return next;
      });
    }
  };

  // Disconnect node
  const handleDisconnectNode = async (node: PeerNode) => {
    setDisconnectingNodes((prev) => new Set(prev).add(node.tag));
    try {
      await api.disconnectPeerNode(node.tag);
      showSuccess(t("peers.disconnectSuccess", { name: node.name }));
      loadNodes();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setError(errorMessage);
    } finally {
      setDisconnectingNodes((prev) => {
        const next = new Set(prev);
        next.delete(node.tag);
        return next;
      });
    }
  };

  // Toggle node selection
  const toggleNodeSelection = (tag: string) => {
    setSelectedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(tag)) {
        next.delete(tag);
      } else {
        next.add(tag);
      }
      return next;
    });
  };

  // Select/deselect all
  const toggleSelectAll = () => {
    if (selectedNodes.size === nodes.length) {
      setSelectedNodes(new Set());
    } else {
      setSelectedNodes(new Set(nodes.map((n) => n.tag)));
    }
  };

  // Batch connect
  const handleBatchConnect = async () => {
    if (selectedNodes.size === 0) return;
    setBatchConnecting(true);
    try {
      await api.batchConnectPeerNodes(Array.from(selectedNodes));
      showSuccess(t("peers.batchConnectSuccess"));
      loadNodes();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setError(errorMessage);
    } finally {
      setBatchConnecting(false);
    }
  };

  // Batch disconnect
  const handleBatchDisconnect = async () => {
    if (selectedNodes.size === 0) return;
    setBatchDisconnecting(true);
    try {
      await api.batchDisconnectPeerNodes(Array.from(selectedNodes));
      showSuccess(t("peers.batchDisconnectSuccess"));
      loadNodes();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setError(errorMessage);
    } finally {
      setBatchDisconnecting(false);
    }
  };

  // Show node details
  const handleShowDetails = (node: PeerNode) => {
    setDetailNode(node);
    setShowDetailModal(true);
  };

  // Render status badge
  const renderStatusBadge = (status: PeerTunnelStatus) => {
    const StatusIcon =
      status === "connected"
        ? CheckCircleIcon
        : status === "connecting"
        ? ClockIcon
        : status === "error"
        ? ExclamationCircleIcon
        : SignalSlashIcon;

    return (
      <span
        className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${statusBgColors[status]} ${statusColors[status]}`}
      >
        <StatusIcon className="w-3.5 h-3.5" />
        {t(`peers.status.${status}`)}
      </span>
    );
  };

  // Render tunnel type badge
  const renderTunnelTypeBadge = (node: PeerNode) => {
    const isWireGuard = node.tunnel_type === "wireguard";
    return (
      <span
        className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
          isWireGuard ? "bg-blue-500/20 text-blue-400" : "bg-purple-500/20 text-purple-400"
        }`}
      >
        {isWireGuard ? t("peers.wireguard") : `${t("peers.xray")} (${node.xray_protocol?.toUpperCase()})`}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <ArrowPathIcon className="w-8 h-8 text-slate-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">{t("peers.title")}</h1>
          <p className="text-slate-400 mt-1">{t("peers.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadNodes}
            className="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg flex items-center gap-2 transition-colors"
          >
            <ArrowPathIcon className="w-4 h-4" />
            <span className="hidden sm:inline">{t("peers.refresh")}</span>
          </button>
          <button
            onClick={handleAddNode}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg flex items-center gap-2 transition-colors"
          >
            <PlusIcon className="w-4 h-4" />
            {t("peers.addNode")}
          </button>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Success message */}
      {successMessage && (
        <div className="bg-green-500/20 border border-green-500/50 rounded-lg p-4 text-green-400 flex items-center gap-2">
          <CheckCircleIcon className="w-5 h-5" />
          {successMessage}
        </div>
      )}

      {/* Batch operations bar */}
      {nodes.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 p-4 bg-slate-800/50 rounded-lg">
          <button
            onClick={toggleSelectAll}
            className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded flex items-center gap-1.5 transition-colors"
          >
            {selectedNodes.size === nodes.length ? (
              <>
                <XMarkIcon className="w-4 h-4" />
                {t("peers.deselectAll")}
              </>
            ) : (
              <>
                <CheckIcon className="w-4 h-4" />
                {t("peers.selectAll")}
              </>
            )}
          </button>

          {selectedNodes.size > 0 && (
            <>
              <span className="text-slate-400 text-sm">
                {t("peers.selectedNodes", { count: selectedNodes.size })}
              </span>
              <button
                onClick={handleBatchConnect}
                disabled={batchConnecting}
                className="px-3 py-1.5 bg-green-600 hover:bg-green-500 disabled:bg-green-600/50 text-white text-sm rounded flex items-center gap-1.5 transition-colors"
              >
                {batchConnecting ? (
                  <>
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                    {t("peers.batchConnecting")}
                  </>
                ) : (
                  <>
                    <LinkIcon className="w-4 h-4" />
                    {t("peers.batchConnect")}
                  </>
                )}
              </button>
              <button
                onClick={handleBatchDisconnect}
                disabled={batchDisconnecting}
                className="px-3 py-1.5 bg-orange-600 hover:bg-orange-500 disabled:bg-orange-600/50 text-white text-sm rounded flex items-center gap-1.5 transition-colors"
              >
                {batchDisconnecting ? (
                  <>
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                    {t("peers.batchDisconnecting")}
                  </>
                ) : (
                  <>
                    <XMarkIcon className="w-4 h-4" />
                    {t("peers.batchDisconnect")}
                  </>
                )}
              </button>
            </>
          )}
        </div>
      )}

      {/* Node list */}
      {nodes.length === 0 ? (
        <div className="text-center py-16 bg-slate-800/50 rounded-lg">
          <ServerStackIcon className="w-16 h-16 text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-400 mb-2">{t("peers.noNodes")}</h3>
          <p className="text-slate-500 mb-6">{t("peers.noNodesHint")}</p>
          <button
            onClick={handleAddNode}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg inline-flex items-center gap-2 transition-colors"
          >
            <PlusIcon className="w-4 h-4" />
            {t("peers.addNode")}
          </button>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {nodes.map((node) => (
            <div
              key={node.tag}
              className={`bg-slate-800 rounded-lg p-4 border transition-colors ${
                selectedNodes.has(node.tag)
                  ? "border-blue-500"
                  : "border-slate-700 hover:border-slate-600"
              }`}
            >
              {/* Card header */}
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    checked={selectedNodes.has(node.tag)}
                    onChange={() => toggleNodeSelection(node.tag)}
                    className="mt-1 w-4 h-4 rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  <div>
                    <h3 className="font-medium text-white">{node.name}</h3>
                    <p className="text-sm text-slate-400 font-mono">{node.tag}</p>
                  </div>
                </div>
                {renderStatusBadge(node.tunnel_status)}
              </div>

              {/* Node info */}
              <div className="space-y-2 mb-4">
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-slate-500">{t("peers.endpoint")}:</span>
                  <span className="text-slate-300 font-mono">{node.endpoint}</span>
                </div>
                <div className="flex items-center gap-2">
                  {renderTunnelTypeBadge(node)}
                  {node.auto_reconnect && (
                    <span className="text-xs text-slate-500 flex items-center gap-1">
                      <ArrowPathIcon className="w-3 h-3" />
                      {t("peers.autoReconnect")}
                    </span>
                  )}
                </div>
                {node.description && (
                  <p className="text-sm text-slate-500 truncate">{node.description}</p>
                )}
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 pt-3 border-t border-slate-700">
                {node.tunnel_status === "connected" ? (
                  <button
                    onClick={() => handleDisconnectNode(node)}
                    disabled={disconnectingNodes.has(node.tag)}
                    className="flex-1 px-3 py-1.5 bg-orange-600 hover:bg-orange-500 disabled:bg-orange-600/50 text-white text-sm rounded flex items-center justify-center gap-1.5 transition-colors"
                  >
                    {disconnectingNodes.has(node.tag) ? (
                      <>
                        <ArrowPathIcon className="w-4 h-4 animate-spin" />
                        {t("peers.disconnecting")}
                      </>
                    ) : (
                      <>
                        <SignalSlashIcon className="w-4 h-4" />
                        {t("peers.disconnect")}
                      </>
                    )}
                  </button>
                ) : (
                  <button
                    onClick={() => handleConnectNode(node)}
                    disabled={connectingNodes.has(node.tag) || node.tunnel_status === "connecting"}
                    className="flex-1 px-3 py-1.5 bg-green-600 hover:bg-green-500 disabled:bg-green-600/50 text-white text-sm rounded flex items-center justify-center gap-1.5 transition-colors"
                  >
                    {connectingNodes.has(node.tag) || node.tunnel_status === "connecting" ? (
                      <>
                        <ArrowPathIcon className="w-4 h-4 animate-spin" />
                        {t("peers.connecting")}
                      </>
                    ) : (
                      <>
                        <SignalIcon className="w-4 h-4" />
                        {t("peers.connect")}
                      </>
                    )}
                  </button>
                )}
                <button
                  onClick={() => handleShowDetails(node)}
                  className="p-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded transition-colors"
                  title={t("peers.nodeDetails")}
                >
                  <ServerStackIcon className="w-4 h-4" />
                </button>
                <button
                  onClick={() => handleEditNode(node)}
                  className="p-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded transition-colors"
                  title={t("common.edit")}
                >
                  <PencilIcon className="w-4 h-4" />
                </button>
                <button
                  onClick={() => handleDeleteNode(node)}
                  className="p-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded transition-colors"
                  title={t("common.delete")}
                >
                  <TrashIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add/Edit Modal */}
      {showModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="peer-modal-title"
              className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg"
            >
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 id="peer-modal-title" className="text-xl font-bold text-white">
                    {editingNode ? t("peers.editNode") : t("peers.addNode")}
                  </h2>
                  <button
                    onClick={handleCloseModal}
                    className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="p-6 space-y-4">
              {formError && (
                <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-3 text-red-400 text-sm">
                  {formError}
                </div>
              )}

              {/* Tag */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("peers.tag")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  name="tag"
                  value={formData.tag}
                  onChange={handleInputChange}
                  disabled={!!editingNode}
                  placeholder={t("peers.tagPlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand disabled:opacity-50"
                />
                <p className="text-xs text-slate-500 mt-1">{t("peers.tagHint")}</p>
              </div>

              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("peers.name")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  placeholder={t("peers.namePlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("peers.description")}
                </label>
                <textarea
                  name="description"
                  value={formData.description}
                  onChange={handleInputChange}
                  placeholder={t("peers.descriptionPlaceholder")}
                  rows={2}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand resize-none"
                />
              </div>

              {/* Endpoint */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("peers.endpoint")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  name="endpoint"
                  value={formData.endpoint}
                  onChange={handleInputChange}
                  placeholder={t("peers.endpointPlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
                <p className="text-xs text-slate-500 mt-1">{t("peers.endpointHint")}</p>
              </div>

              {/* PSK - [CR-006] Changed to password type with visibility toggle */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("peers.psk")} {!editingNode && <span className="text-red-400">*</span>}
                </label>
                <div className="flex gap-2">
                  <div className="flex-1 relative">
                    <input
                      type={showPsk ? "text" : "password"}
                      name="psk"
                      value={formData.psk}
                      onChange={handleInputChange}
                      placeholder={editingNode ? t("peers.pskPlaceholderEdit") : t("peers.pskPlaceholder")}
                      autoComplete="new-password"
                      className="w-full px-3 py-2 pr-10 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-sm placeholder-slate-500 focus:outline-none focus:border-brand"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPsk(!showPsk)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
                      title={showPsk ? t("peers.hidePsk") : t("peers.showPsk")}
                    >
                      {showPsk ? (
                        <EyeSlashIcon className="h-5 w-5" />
                      ) : (
                        <EyeIcon className="h-5 w-5" />
                      )}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      // 生成 32 字节随机密钥，Base64 编码
                      const bytes = new Uint8Array(32);
                      crypto.getRandomValues(bytes);
                      const base64 = btoa(String.fromCharCode(...bytes));
                      setFormData(prev => ({ ...prev, psk: base64 }));
                      setShowPsk(true);  // Show PSK when generating to verify
                    }}
                    className="px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 transition-colors flex items-center gap-1.5"
                    title={t("peers.generatePsk")}
                  >
                    <KeyIcon className="h-4 w-4" />
                    <span className="hidden sm:inline text-sm">{t("peers.generate")}</span>
                  </button>
                </div>
                <p className="text-xs text-slate-500 mt-1">{t("peers.pskHint")}</p>
              </div>

              {/* Tunnel Type (only for new nodes) */}
              {!editingNode && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("peers.tunnelType")}
                  </label>
                  <div className="flex gap-4">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="tunnel_type"
                        value="wireguard"
                        checked={formData.tunnel_type === "wireguard"}
                        onChange={handleInputChange}
                        className="w-4 h-4 text-brand bg-white/5 border-white/10 focus:ring-brand focus:ring-offset-0"
                      />
                      <span className="text-slate-300">{t("peers.wireguard")}</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="tunnel_type"
                        value="xray"
                        checked={formData.tunnel_type === "xray"}
                        onChange={handleInputChange}
                        className="w-4 h-4 text-brand bg-white/5 border-white/10 focus:ring-brand focus:ring-offset-0"
                      />
                      <span className="text-slate-300">{t("peers.xray")}</span>
                    </label>
                  </div>
                </div>
              )}

              {/* Xray Protocol (only for Xray tunnel type) */}
              {!editingNode && formData.tunnel_type === "xray" && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("peers.xrayProtocol")}
                  </label>
                  <select
                    name="xray_protocol"
                    value={formData.xray_protocol}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                  >
                    <option value="vless">{t("peers.vless")}</option>
                    <option value="vmess">{t("peers.vmess")}</option>
                    <option value="trojan">{t("peers.trojan")}</option>
                  </select>
                </div>
              )}

              {/* TLS Verification (only for Xray Trojan protocol) */}
              {formData.tunnel_type === "xray" && formData.xray_protocol === "trojan" && (
                <>
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      id="tls_verify"
                      name="tls_verify"
                      checked={formData.tls_verify}
                      onChange={handleInputChange}
                      className="w-4 h-4 rounded border-white/10 bg-white/5 text-brand focus:ring-brand focus:ring-offset-0"
                    />
                    <label htmlFor="tls_verify" className="text-slate-300">
                      {t("peers.tlsVerify")}
                    </label>
                  </div>
                  {!formData.tls_verify && (
                    <p className="text-xs text-yellow-500 -mt-2 ml-7">{t("peers.tlsVerifyWarning")}</p>
                  )}

                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">
                      {t("peers.tlsFingerprint")}
                      <span className="text-slate-500 ml-2">({t("common.optional")})</span>
                    </label>
                    <input
                      type="text"
                      name="tls_fingerprint"
                      value={formData.tls_fingerprint}
                      onChange={handleInputChange}
                      placeholder={t("peers.tlsFingerprintPlaceholder")}
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                    />
                    <p className="text-xs text-slate-500 mt-1">{t("peers.tlsFingerprintHint")}</p>
                  </div>
                </>
              )}

              {/* Auto Reconnect */}
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="auto_reconnect"
                  name="auto_reconnect"
                  checked={formData.auto_reconnect}
                  onChange={handleInputChange}
                  className="w-4 h-4 rounded border-white/10 bg-white/5 text-brand focus:ring-brand focus:ring-offset-0"
                />
                <label htmlFor="auto_reconnect" className="text-slate-300">
                  {t("peers.autoReconnect")}
                </label>
              </div>
              <p className="text-xs text-slate-500 -mt-2 ml-7">{t("peers.autoReconnectHint")}</p>
              </form>

              <div className="p-6 border-t border-white/10 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={handleCloseModal}
                  className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
                >
                  {t("common.cancel")}
                </button>
                <button
                  onClick={(e) => {
                    e.preventDefault();
                    const form = document.querySelector('form');
                    if (form) form.requestSubmit();
                  }}
                  disabled={saving}
                  className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  {saving ? (
                    <>
                      <ArrowPathIcon className="h-4 w-4 animate-spin" />
                      {t("common.saving")}
                    </>
                  ) : (
                    t("common.save")
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Detail Modal */}
      {showDetailModal && detailNode && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="peer-detail-modal-title"
              className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg"
            >
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 id="peer-detail-modal-title" className="text-xl font-bold text-white">{t("peers.nodeDetails")}</h2>
                  <button
                    onClick={() => setShowDetailModal(false)}
                    className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>

              <div className="p-6 space-y-4">
                {/* Basic info */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-slate-500 mb-1">{t("peers.name")}</label>
                    <p className="text-white">{detailNode.name}</p>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-500 mb-1">{t("peers.tag")}</label>
                    <p className="text-white font-mono">{detailNode.tag}</p>
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("peers.endpoint")}</label>
                  <p className="text-white font-mono">{detailNode.endpoint}</p>
                </div>

                {detailNode.description && (
                  <div>
                    <label className="block text-xs text-slate-500 mb-1">{t("peers.description")}</label>
                    <p className="text-slate-300">{detailNode.description}</p>
                  </div>
                )}

                {/* Status info */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-slate-500 mb-1">{t("peers.tunnelStatus")}</label>
                    {renderStatusBadge(detailNode.tunnel_status)}
                  </div>
                  <div>
                    <label className="block text-xs text-slate-500 mb-1">{t("peers.tunnelType")}</label>
                    {renderTunnelTypeBadge(detailNode)}
                  </div>
                </div>

                {/* Tunnel details (when connected) */}
                {detailNode.tunnel_status === "connected" && (
                  <>
                    {detailNode.tunnel_interface && (
                      <div>
                        <label className="block text-xs text-slate-500 mb-1">{t("peers.tunnelInterface")}</label>
                        <p className="text-white font-mono">{detailNode.tunnel_interface}</p>
                      </div>
                    )}
                    <div className="grid grid-cols-2 gap-4">
                      {detailNode.tunnel_local_ip && (
                        <div>
                          <label className="block text-xs text-slate-500 mb-1">{t("peers.tunnelLocalIp")}</label>
                          <p className="text-white font-mono">{detailNode.tunnel_local_ip}</p>
                        </div>
                      )}
                      {detailNode.tunnel_remote_ip && (
                        <div>
                          <label className="block text-xs text-slate-500 mb-1">{t("peers.tunnelRemoteIp")}</label>
                          <p className="text-white font-mono">{detailNode.tunnel_remote_ip}</p>
                        </div>
                      )}
                    </div>
                  </>
                )}

                {/* Last seen / error */}
                {detailNode.last_seen && (
                  <div>
                    <label className="block text-xs text-slate-500 mb-1">{t("peers.lastSeen")}</label>
                    <p className="text-slate-300">{new Date(detailNode.last_seen).toLocaleString()}</p>
                  </div>
                )}

                {detailNode.last_error && (
                  <div>
                    <label className="block text-xs text-slate-500 mb-1">{t("peers.lastError")}</label>
                    <p className="text-red-400 text-sm">{detailNode.last_error}</p>
                  </div>
                )}
              </div>

              <div className="p-6 border-t border-white/10 flex justify-end">
                <button
                  onClick={() => setShowDetailModal(false)}
                  className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
                >
                  {t("common.close")}
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* [CR-009] Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={deleteConfirmOpen}
        title={t("peers.confirmDeleteTitle")}
        message={
          nodeToDelete ? (
            <span>
              {t("peers.confirmDeleteMessage", { name: nodeToDelete.name })}
              <br />
              <span className="text-slate-400 text-xs mt-1 block">
                Tag: <code className="font-mono">{nodeToDelete.tag}</code>
              </span>
            </span>
          ) : null
        }
        confirmText={t("common.delete")}
        variant="danger"
        onConfirm={confirmDeleteNode}
        onCancel={cancelDeleteNode}
      />
    </div>
  );
}
