import { useState, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { IngressResponse, IngressPeer } from "../types";
import {
  PlusIcon,
  TrashIcon,
  ArrowPathIcon,
  ArrowDownTrayIcon,
  QrCodeIcon,
  ClipboardDocumentIcon,
  XMarkIcon,
  CheckIcon,
  WifiIcon,
  ComputerDesktopIcon,
  DevicePhoneMobileIcon,
  Cog6ToothIcon
} from "@heroicons/react/24/outline";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export default function IngressManager() {
  const { t } = useTranslation();
  const [ingress, setIngress] = useState<IngressResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const formatLastSeen = (timestamp: number): string => {
    if (timestamp === 0) return t("ingress.neverConnected");
    const now = Math.floor(Date.now() / 1000);
    const diff = now - timestamp;
    if (diff < 60) return t("ingress.justNow");
    if (diff < 3600) return t("ingress.minutesAgo", { count: Math.floor(diff / 60) });
    if (diff < 86400) return t("ingress.hoursAgo", { count: Math.floor(diff / 3600) });
    return t("ingress.daysAgo", { count: Math.floor(diff / 86400) });
  };

  // Add peer modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [newPeerName, setNewPeerName] = useState("");
  const [newPeerPublicKey, setNewPeerPublicKey] = useState("");
  const [useCustomKey, setUseCustomKey] = useState(false);
  const [allowLan, setAllowLan] = useState(false);

  // Config modal (shows after adding peer or for existing peer)
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [configPeerName, setConfigPeerName] = useState("");
  const [configPrivateKey, setConfigPrivateKey] = useState("");
  const [configCopied, setConfigCopied] = useState(false);
  const [configQrCodeUrl, setConfigQrCodeUrl] = useState<string | null>(null);

  // Settings
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [serverEndpoint, setServerEndpoint] = useState("");
  const [serverEndpointSaved, setServerEndpointSaved] = useState("");
  const [savingSettings, setSavingSettings] = useState(false);
  const [detectedIps, setDetectedIps] = useState<{ public_ip: string | null; lan_ip: string | null } | null>(null);
  const [detectingIp, setDetectingIp] = useState(false);

  const detectIp = useCallback(async () => {
    setDetectingIp(true);
    try {
      const result = await api.detectIp();
      setDetectedIps({ public_ip: result.public_ip, lan_ip: result.lan_ip });
      return result;
    } catch {
      setDetectedIps(null);
      return null;
    } finally {
      setDetectingIp(false);
    }
  }, []);

  const loadSettings = useCallback(async () => {
    try {
      const settings = await api.getSettings();
      setServerEndpoint(settings.server_endpoint || "");
      setServerEndpointSaved(settings.server_endpoint || "");
    } catch {
      // Ignore errors
    }
  }, []);

  const loadIngress = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getIngress();
      setIngress(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    loadIngress();
    loadSettings();
    const interval = setInterval(loadIngress, 30000);
    return () => clearInterval(interval);
  }, [loadIngress, loadSettings]);

  const handleSaveSettings = async () => {
    setSavingSettings(true);
    try {
      await api.updateSettings(serverEndpoint.trim());
      setServerEndpointSaved(serverEndpoint.trim());
      setSuccessMessage(t("ingress.serverAddressSaved"));
      setShowSettingsModal(false);
      setDetectedIps(null);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.saveFailed"));
    } finally {
      setSavingSettings(false);
    }
  };

  const handleAddPeer = async () => {
    if (!newPeerName.trim()) {
      setError(t("ingress.pleaseEnterClientName"));
      return;
    }

    setActionLoading("add");
    try {
      // Save server endpoint if it was set in the modal
      if (!serverEndpointSaved && serverEndpoint.trim()) {
        await api.updateSettings(serverEndpoint.trim());
        setServerEndpointSaved(serverEndpoint.trim());
      }

      const result = await api.addIngressPeer(
        newPeerName.trim(),
        useCustomKey ? newPeerPublicKey.trim() : undefined,
        allowLan
      );
      setSuccessMessage(t("ingress.clientAdded", { name: newPeerName.trim() }));
      setShowAddModal(false);
      setNewPeerName("");
      setNewPeerPublicKey("");
      setUseCustomKey(false);
      setAllowLan(false);
      setDetectedIps(null);

      if (result.client_private_key) {
        setConfigPeerName(newPeerName.trim());
        setConfigPrivateKey(result.client_private_key);
        setShowConfigModal(true);
      }

      loadIngress();
      setTimeout(() => setSuccessMessage(null), 5000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("ingress.addFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeletePeer = async (name: string) => {
    if (!confirm(t("ingress.confirmDelete", { name }))) return;

    setActionLoading(`delete-${name}`);
    try {
      await api.deleteIngressPeer(name);
      setSuccessMessage(t("ingress.clientDeleted", { name }));
      loadIngress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.deleteFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleShowConfig = (peer: IngressPeer) => {
    setConfigPeerName(peer.name);
    setConfigPrivateKey("");
    setShowConfigModal(true);
  };

  // 关闭 config modal 并清理 blob URL
  const handleCloseConfigModal = () => {
    if (configQrCodeUrl) {
      URL.revokeObjectURL(configQrCodeUrl);
    }
    setShowConfigModal(false);
    setConfigPeerName("");
    setConfigPrivateKey("");
    setConfigQrCodeUrl(null);
  };

  // 当 config modal 显示时或私钥改变时，异步获取二维码
  useEffect(() => {
    if (!showConfigModal || !configPeerName) {
      return;
    }

    let cancelled = false;
    const fetchQrCode = async () => {
      try {
        // 先清理旧的 blob URL
        if (configQrCodeUrl) {
          URL.revokeObjectURL(configQrCodeUrl);
        }
        const blobUrl = await api.getIngressPeerQrcode(configPeerName, configPrivateKey || undefined);
        if (!cancelled) {
          setConfigQrCodeUrl(blobUrl);
        } else {
          URL.revokeObjectURL(blobUrl);
        }
      } catch {
        // 二维码获取失败，不显示
        if (!cancelled) {
          setConfigQrCodeUrl(null);
        }
      }
    };

    fetchQrCode();

    return () => {
      cancelled = true;
    };
  }, [showConfigModal, configPeerName, configPrivateKey]);

  const handleCopyConfig = async () => {
    const configUrl = api.getIngressPeerConfigUrl(configPeerName, configPrivateKey || undefined);
    try {
      const response = await fetch(configUrl);
      const text = await response.text();
      await navigator.clipboard.writeText(text);
      setConfigCopied(true);
      setTimeout(() => setConfigCopied(false), 2000);
    } catch {
      setError(t("common.copyFailed"));
    }
  };

  const handleDownloadConfig = () => {
    const configUrl = api.getIngressPeerConfigUrl(configPeerName, configPrivateKey || undefined);
    const link = document.createElement("a");
    link.href = configUrl;
    link.download = `${configPeerName}.conf`;
    link.click();
  };

  const getPeerIcon = (name: string) => {
    const lower = name.toLowerCase();
    if (lower.includes("phone") || lower.includes("mobile") || lower.includes("iphone") || lower.includes("android")) {
      return DevicePhoneMobileIcon;
    }
    return ComputerDesktopIcon;
  };

  if (loading && !ingress) {
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
          <h1 className="text-2xl font-bold text-white">{t("ingress.title")}</h1>
          <p className="text-slate-400 mt-1">{t("ingress.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowSettingsModal(true)}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
            title={t("ingress.settings")}
          >
            <Cog6ToothIcon className="h-5 w-5 text-slate-400" />
          </button>
          <button
            onClick={loadIngress}
            disabled={loading}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors disabled:opacity-50"
            title={t("common.refresh")}
          >
            <ArrowPathIcon className={`h-5 w-5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white font-medium transition-colors"
          >
            <PlusIcon className="h-5 w-5" />
            {t("ingress.addClient")}
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-4 text-red-400">
          {error}
          <button onClick={() => setError(null)} className="float-right">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
      )}
      {successMessage && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/20 p-4 text-emerald-400 flex items-center gap-2">
          <CheckIcon className="h-5 w-5" />
          {successMessage}
        </div>
      )}

      {/* Interface Info */}
      {ingress && (
        <div className="rounded-xl bg-white/5 border border-white/10 p-5">
          <h3 className="text-sm font-semibold text-slate-400 mb-3">{t("ingress.ingressInterface")}</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-xs text-slate-500">{t("ingress.interfaceName")}</p>
              <p className="font-mono text-white">{ingress.interface.name}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">{t("ingress.listenPort")}</p>
              <p className="font-mono text-white">{ingress.interface.listen_port}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">{t("common.address")}</p>
              <p className="font-mono text-white">{ingress.interface.address}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">MTU</p>
              <p className="font-mono text-white">{ingress.interface.mtu}</p>
            </div>
          </div>
          {ingress.interface.public_key && (
            <div className="mt-3 pt-3 border-t border-white/5">
              <p className="text-xs text-slate-500 mb-1">{t("ingress.serverPublicKey")}</p>
              <p className="font-mono text-xs text-slate-300 break-all">{ingress.interface.public_key}</p>
            </div>
          )}
        </div>
      )}

      {/* Peers List */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-400">
          {t("ingress.connectedClients")} ({ingress?.peer_count || 0})
        </h3>

        {ingress?.peers.length === 0 ? (
          <div className="rounded-xl bg-white/5 border border-white/10 p-12 text-center">
            <WifiIcon className="h-12 w-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">{t("ingress.noClientsYet")}</p>
            <button
              onClick={() => setShowAddModal(true)}
              className="mt-4 px-4 py-2 rounded-lg bg-brand text-white text-sm font-medium"
            >
              {t("ingress.addFirstClient")}
            </button>
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {ingress?.peers.map((peer) => {
              const PeerIcon = getPeerIcon(peer.name);
              return (
                <div
                  key={peer.name}
                  className={`rounded-xl border p-4 transition-all ${
                    peer.is_online
                      ? "bg-emerald-500/5 border-emerald-500/20"
                      : "bg-white/5 border-white/10"
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${peer.is_online ? "bg-emerald-500/20" : "bg-white/10"}`}>
                        <PeerIcon className={`h-5 w-5 ${peer.is_online ? "text-emerald-400" : "text-slate-400"}`} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="font-semibold text-white">{peer.name}</h4>
                          <span className={`w-2 h-2 rounded-full ${peer.is_online ? "bg-emerald-400" : "bg-slate-500"}`} />
                        </div>
                        <p className="text-xs text-slate-500">{peer.allowed_ips.join(", ")}</p>
                      </div>
                    </div>
                    <div className="flex gap-1">
                      <button
                        onClick={() => handleShowConfig(peer)}
                        className="p-2 rounded-lg text-slate-400 hover:bg-white/10 hover:text-white"
                        title={t("ingress.getConfig")}
                      >
                        <QrCodeIcon className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDeletePeer(peer.name)}
                        disabled={actionLoading === `delete-${peer.name}`}
                        className="p-2 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                        title={t("common.delete")}
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t border-white/5 grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <p className="text-slate-500">{t("ingress.clientStatus")}</p>
                      <p className={peer.is_online ? "text-emerald-400" : "text-slate-400"}>
                        {peer.is_online ? t("ingress.active") : t("ingress.idle")}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">{t("ingress.lastHandshake")}</p>
                      <p className="text-slate-300">{formatLastSeen(peer.last_handshake)}</p>
                    </div>
                    <div>
                      <p className="text-slate-500">{t("ingress.traffic")}</p>
                      <p className="text-slate-300">
                        ↓{formatBytes(peer.rx_bytes)} ↑{formatBytes(peer.tx_bytes)}
                      </p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Add Peer Modal */}
      {showAddModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-md">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">{t("ingress.addClient")}</h2>
                <button
                  onClick={() => setShowAddModal(false)}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("ingress.clientName")} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={newPeerName}
                  onChange={(e) => setNewPeerName(e.target.value)}
                  placeholder={t("ingress.clientNamePlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              {/* Server Address Setup - show if not configured */}
              {!serverEndpointSaved && (
                <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-4 space-y-3">
                  <div className="flex items-center gap-2">
                    <Cog6ToothIcon className="h-4 w-4 text-amber-400" />
                    <span className="text-sm font-medium text-amber-300">
                      {t("ingress.setupServerAddress")}
                    </span>
                  </div>
                  <p className="text-xs text-amber-200/70">
                    {t("ingress.setupServerAddressHint")}
                  </p>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={serverEndpoint}
                      onChange={(e) => setServerEndpoint(e.target.value)}
                      placeholder={t("ingress.serverAddressPlaceholder")}
                      className="flex-1 px-3 py-2 rounded-lg bg-black/20 border border-amber-500/30 text-white placeholder-slate-500 focus:outline-none focus:border-amber-400 text-sm"
                    />
                    <button
                      onClick={detectIp}
                      disabled={detectingIp}
                      className="px-3 py-2 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-sm transition-colors disabled:opacity-50 whitespace-nowrap"
                    >
                      {detectingIp ? (
                        <div className="animate-spin h-4 w-4 border-2 border-amber-400 border-t-transparent rounded-full" />
                      ) : (
                        t("ingress.autoDetect")
                      )}
                    </button>
                  </div>
                  {detectedIps && (detectedIps.public_ip || detectedIps.lan_ip) && (
                    <div className="flex flex-wrap gap-2 mt-2">
                      {detectedIps.public_ip && (
                        <button
                          onClick={() => setServerEndpoint(detectedIps.public_ip!)}
                          className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${
                            serverEndpoint === detectedIps.public_ip
                              ? "bg-amber-500/30 border border-amber-400 text-amber-200"
                              : "bg-black/20 border border-amber-500/20 text-amber-300 hover:bg-amber-500/20"
                          }`}
                        >
                          {t("ingress.publicIp")}: {detectedIps.public_ip}
                        </button>
                      )}
                      {detectedIps.lan_ip && (
                        <button
                          onClick={() => setServerEndpoint(detectedIps.lan_ip!)}
                          className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${
                            serverEndpoint === detectedIps.lan_ip
                              ? "bg-amber-500/30 border border-amber-400 text-amber-200"
                              : "bg-black/20 border border-amber-500/20 text-amber-300 hover:bg-amber-500/20"
                          }`}
                        >
                          {t("ingress.lanIp")}: {detectedIps.lan_ip}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}

              <div>
                <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useCustomKey}
                    onChange={(e) => setUseCustomKey(e.target.checked)}
                    className="rounded border-slate-600"
                  />
                  {t("ingress.useCustomPublicKey")}
                </label>
              </div>

              {/* LAN Access Option */}
              <div>
                <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={allowLan}
                    onChange={(e) => {
                      setAllowLan(e.target.checked);
                      if (e.target.checked && !detectedIps) {
                        detectIp();
                      }
                    }}
                    className="rounded border-slate-600"
                  />
                  {t("ingress.allowLanAccess")}
                </label>
                <p className="text-xs text-slate-500 mt-1 ml-5">
                  {t("ingress.allowLanAccessHint")}
                </p>
                {allowLan && detectedIps?.lan_ip && (
                  <p className="text-xs text-emerald-400 mt-1 ml-5">
                    {t("ingress.detectedLanSubnet")}: {detectedIps.lan_ip.split('.').slice(0, 3).join('.')}.0/24
                  </p>
                )}
                {allowLan && !detectedIps?.lan_ip && !detectingIp && (
                  <p className="text-xs text-amber-400 mt-1 ml-5">
                    {t("ingress.cannotDetectLan")}
                  </p>
                )}
              </div>

              {useCustomKey && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("ingress.clientPublicKey")}
                  </label>
                  <input
                    type="text"
                    value={newPeerPublicKey}
                    onChange={(e) => setNewPeerPublicKey(e.target.value)}
                    placeholder={t("ingress.publicKeyPlaceholder")}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-sm placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    {t("ingress.publicKeyHint")}
                  </p>
                </div>
              )}

              {!useCustomKey && (
                <div className="rounded-lg bg-blue-500/10 border border-blue-500/20 p-3">
                  <p className="text-xs text-blue-300">
                    {t("ingress.autoGenerateKeyHint")}
                  </p>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t("common.cancel")}
              </button>
              <button
                onClick={handleAddPeer}
                disabled={actionLoading === "add"}
                className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {actionLoading === "add" ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : (
                  <PlusIcon className="h-4 w-4" />
                )}
                {t("ingress.add")}
              </button>
            </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Config Modal */}
      {showConfigModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-bold text-white">{t("ingress.clientConfig")} - {configPeerName}</h2>
                <button
                  onClick={handleCloseConfigModal}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              {!configPrivateKey && (
                <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-3">
                  <p className="text-xs text-amber-300">
                    {t("ingress.privateKeyHint")}
                  </p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t("ingress.clientPrivateKey")}
                </label>
                <input
                  type="text"
                  value={configPrivateKey}
                  onChange={(e) => setConfigPrivateKey(e.target.value)}
                  placeholder={t("ingress.privateKeyPlaceholder")}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-sm placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              {/* QR Code */}
              {configQrCodeUrl && (
                <div className="flex justify-center py-4">
                  <div className="bg-white p-2 rounded-lg">
                    <img
                      src={configQrCodeUrl}
                      alt={t("ingress.qrCodeAlt")}
                      className="w-48 h-48"
                    />
                  </div>
                </div>
              )}

              <p className="text-xs text-slate-500 text-center">
                {t("ingress.qrCodeHint")}
              </p>
            </div>

            <div className="p-6 border-t border-white/10 flex justify-center gap-3">
              <button
                onClick={handleCopyConfig}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {configCopied ? (
                  <>
                    <CheckIcon className="h-4 w-4 text-emerald-400" />
                    {t("ingress.copied")}
                  </>
                ) : (
                  <>
                    <ClipboardDocumentIcon className="h-4 w-4" />
                    {t("ingress.copyConfig")}
                  </>
                )}
              </button>
              <button
                onClick={handleDownloadConfig}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors"
              >
                <ArrowDownTrayIcon className="h-4 w-4" />
                {t("ingress.downloadConf")}
              </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Settings Modal */}
      {showSettingsModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-md">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">{t("ingress.ingressSettings")}</h2>
                <button
                  onClick={() => {
                    setShowSettingsModal(false);
                    setServerEndpoint(serverEndpointSaved);
                    setDetectedIps(null);
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
                  {t("ingress.serverPublicAddress")} <span className="text-red-400">*</span>
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={serverEndpoint}
                    onChange={(e) => setServerEndpoint(e.target.value)}
                    placeholder={t("ingress.serverAddressPlaceholder")}
                    className="flex-1 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                  <button
                    onClick={detectIp}
                    disabled={detectingIp}
                    className="px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors disabled:opacity-50 whitespace-nowrap"
                    title={t("ingress.autoDetect")}
                  >
                    {detectingIp ? (
                      <div className="animate-spin h-4 w-4 border-2 border-slate-400 border-t-transparent rounded-full" />
                    ) : (
                      t("ingress.autoDetect")
                    )}
                  </button>
                </div>
                <p className="text-xs text-slate-500 mt-2">
                  {t("ingress.serverAddressHint", { port: ingress?.interface.listen_port || 36100 })}
                </p>
              </div>

              {/* Detected IPs selection */}
              {detectedIps && (detectedIps.public_ip || detectedIps.lan_ip) && (
                <div className="rounded-lg bg-blue-500/10 border border-blue-500/20 p-4 space-y-3">
                  <p className="text-xs text-blue-300">{t("ingress.selectDetectedIp")}</p>
                  <div className="flex flex-wrap gap-2">
                    {detectedIps.public_ip && (
                      <button
                        onClick={() => setServerEndpoint(detectedIps.public_ip!)}
                        className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                          serverEndpoint === detectedIps.public_ip
                            ? "bg-blue-500/30 border border-blue-400 text-blue-200"
                            : "bg-white/5 border border-white/10 text-slate-300 hover:bg-white/10"
                        }`}
                      >
                        {t("ingress.publicIp")}: {detectedIps.public_ip}
                      </button>
                    )}
                    {detectedIps.lan_ip && (
                      <button
                        onClick={() => setServerEndpoint(detectedIps.lan_ip!)}
                        className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                          serverEndpoint === detectedIps.lan_ip
                            ? "bg-blue-500/30 border border-blue-400 text-blue-200"
                            : "bg-white/5 border border-white/10 text-slate-300 hover:bg-white/10"
                        }`}
                      >
                        {t("ingress.lanIp")}: {detectedIps.lan_ip}
                      </button>
                    )}
                  </div>
                </div>
              )}

              {!serverEndpointSaved && !detectedIps && !serverEndpoint && (
                <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-3">
                  <p className="text-xs text-amber-300">
                    {t("ingress.noServerAddressWarning")}
                  </p>
                </div>
              )}

              {serverEndpointSaved && (
                <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-3">
                  <p className="text-xs text-emerald-300">
                    {t("ingress.currentServerAddress")}: {serverEndpointSaved}:{ingress?.interface.listen_port || 36100}
                  </p>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowSettingsModal(false);
                  setServerEndpoint(serverEndpointSaved);
                  setDetectedIps(null);
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t("common.cancel")}
              </button>
              <button
                onClick={handleSaveSettings}
                disabled={savingSettings || !serverEndpoint.trim()}
                className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {savingSettings ? (
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
