import { useState, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { V2RayInboundConfig, V2RayUser, V2RayProtocol, V2RayTransport, XrayStatus } from "../types";
import { V2RAY_PROTOCOLS, V2RAY_TRANSPORTS } from "../types";
import {
  PlusIcon,
  TrashIcon,
  ArrowPathIcon,
  ClipboardDocumentIcon,
  XMarkIcon,
  CheckIcon,
  ServerIcon,
  UserPlusIcon,
  ShareIcon,
  Cog6ToothIcon,
  KeyIcon,
  BoltIcon,
  SignalIcon
} from "@heroicons/react/24/outline";

export default function V2RayIngressManager() {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // V2Ray Inbound
  const [v2rayConfig, setV2rayConfig] = useState<V2RayInboundConfig | null>(null);
  const [v2rayUsers, setV2rayUsers] = useState<V2RayUser[]>([]);
  const [v2rayLoading, setV2rayLoading] = useState(true);
  const [showV2rayConfigModal, setShowV2rayConfigModal] = useState(false);
  const [showAddV2rayUserModal, setShowAddV2rayUserModal] = useState(false);
  const [v2rayFormEnabled, setV2rayFormEnabled] = useState(false);
  const [v2rayFormProtocol, setV2rayFormProtocol] = useState<V2RayProtocol>("vless");
  const [v2rayFormListenAddress, setV2rayFormListenAddress] = useState("0.0.0.0");
  const [v2rayFormPort, setV2rayFormPort] = useState(443);
  const [v2rayFormTlsEnabled, setV2rayFormTlsEnabled] = useState(true);
  const [v2rayFormTlsCertPath, setV2rayFormTlsCertPath] = useState("");
  const [v2rayFormTlsKeyPath, setV2rayFormTlsKeyPath] = useState("");
  const [v2rayFormTransportType, setV2rayFormTransportType] = useState<V2RayTransport>("tcp");
  // Transport-specific config
  const [v2rayFormWsPath, setV2rayFormWsPath] = useState("/");
  const [v2rayFormWsHost, setV2rayFormWsHost] = useState("");
  const [v2rayFormGrpcServiceName, setV2rayFormGrpcServiceName] = useState("grpc");
  const [v2rayFormGrpcAuthority, setV2rayFormGrpcAuthority] = useState("");
  const [v2rayFormHttpHost, setV2rayFormHttpHost] = useState("");
  const [v2rayFormHttpPath, setV2rayFormHttpPath] = useState("/");
  // XHTTP-specific config
  const [v2rayFormXhttpPath, setV2rayFormXhttpPath] = useState("/");
  const [v2rayFormXhttpMode, setV2rayFormXhttpMode] = useState<"auto" | "packet-up" | "stream-up" | "stream-one">("auto");
  const [v2rayFormXhttpHost, setV2rayFormXhttpHost] = useState("");
  // Fallback config (VLESS/Trojan)
  const [v2rayFormFallbackServer, setV2rayFormFallbackServer] = useState("");
  const [v2rayFormFallbackPort, setV2rayFormFallbackPort] = useState(80);
  // Xray/REALITY form fields
  const [v2rayFormXtlsVision, setV2rayFormXtlsVision] = useState(false);
  const [v2rayFormRealityEnabled, setV2rayFormRealityEnabled] = useState(false);
  const [v2rayFormRealityPrivateKey, setV2rayFormRealityPrivateKey] = useState("");
  const [v2rayFormRealityPublicKey, setV2rayFormRealityPublicKey] = useState("");
  const [v2rayFormRealityShortIds, setV2rayFormRealityShortIds] = useState("");
  const [v2rayFormRealityDest, setV2rayFormRealityDest] = useState("www.microsoft.com:443");
  const [v2rayFormRealityServerNames, setV2rayFormRealityServerNames] = useState("");
  // Xray status
  const [xrayStatus, setXrayStatus] = useState<XrayStatus | null>(null);
  const [newV2rayUserName, setNewV2rayUserName] = useState("");
  const [newV2rayUserEmail, setNewV2rayUserEmail] = useState("");
  const [shareUri, setShareUri] = useState<string | null>(null);
  const [shareUriUser, setShareUriUser] = useState<string | null>(null);
  const [shareQrCodeUrl, setShareQrCodeUrl] = useState<string | null>(null);
  // User online status: {email: online}
  const [userOnlineStatus, setUserOnlineStatus] = useState<Record<string, boolean>>({});

  const loadV2rayInbound = useCallback(async () => {
    try {
      setV2rayLoading(true);
      const data = await api.getV2RayInbound();
      setV2rayConfig(data.config);
      setV2rayUsers(data.users);
    } catch {
      // V2Ray inbound may not be configured yet, ignore errors
    } finally {
      setV2rayLoading(false);
    }
  }, []);

  const loadXrayStatus = useCallback(async () => {
    try {
      const status = await api.getXrayStatus();
      setXrayStatus(status);
    } catch {
      // Xray status may not be available
      setXrayStatus(null);
    }
  }, []);

  const loadUserOnlineStatus = useCallback(async () => {
    try {
      const status = await api.getV2RayUsersOnline();
      const onlineMap: Record<string, boolean> = {};
      for (const [email, data] of Object.entries(status)) {
        onlineMap[email] = data.online;
      }
      setUserOnlineStatus(onlineMap);
    } catch {
      // Ignore errors
    }
  }, []);

  useEffect(() => {
    loadV2rayInbound();
    loadXrayStatus();
  }, [loadV2rayInbound, loadXrayStatus]);

  // Poll user online status every 5 seconds
  useEffect(() => {
    loadUserOnlineStatus();
    const interval = setInterval(loadUserOnlineStatus, 5000);
    return () => clearInterval(interval);
  }, [loadUserOnlineStatus]);

  // V2Ray handlers
  const handleOpenV2rayConfig = () => {
    if (v2rayConfig) {
      setV2rayFormEnabled(v2rayConfig.enabled === 1);
      setV2rayFormProtocol(v2rayConfig.protocol);
      setV2rayFormListenAddress(v2rayConfig.listen_address || "0.0.0.0");
      setV2rayFormPort(v2rayConfig.listen_port);
      setV2rayFormTlsEnabled(v2rayConfig.tls_enabled === 1);
      setV2rayFormTlsCertPath(v2rayConfig.tls_cert_path || "");
      setV2rayFormTlsKeyPath(v2rayConfig.tls_key_path || "");
      setV2rayFormTransportType(v2rayConfig.transport_type);
      // Transport-specific config - parse from transport_config JSON
      const transportConfig = v2rayConfig.transport_config ?
        (typeof v2rayConfig.transport_config === 'string' ?
          JSON.parse(v2rayConfig.transport_config) : v2rayConfig.transport_config) : {};
      setV2rayFormWsPath(transportConfig.path || "/");
      setV2rayFormWsHost(transportConfig.host || "");
      setV2rayFormGrpcServiceName(transportConfig.service_name || "grpc");
      setV2rayFormGrpcAuthority(transportConfig.authority || "");
      setV2rayFormHttpHost(transportConfig.host || "");
      setV2rayFormHttpPath(transportConfig.path || "/");
      // XHTTP config
      setV2rayFormXhttpPath(transportConfig.path || "/");
      setV2rayFormXhttpMode(transportConfig.mode || "auto");
      setV2rayFormXhttpHost(transportConfig.host || "");
      // Fallback config
      setV2rayFormFallbackServer(v2rayConfig.fallback_server || "");
      setV2rayFormFallbackPort(v2rayConfig.fallback_port || 80);
      // XTLS/REALITY fields
      setV2rayFormXtlsVision(v2rayConfig.xtls_vision_enabled === 1);
      setV2rayFormRealityEnabled(v2rayConfig.reality_enabled === 1);
      setV2rayFormRealityPrivateKey(v2rayConfig.reality_private_key || "");
      setV2rayFormRealityPublicKey(v2rayConfig.reality_public_key || "");
      setV2rayFormRealityShortIds((v2rayConfig.reality_short_ids || []).join(", "));
      setV2rayFormRealityDest(v2rayConfig.reality_dest || "www.microsoft.com:443");
      setV2rayFormRealityServerNames((v2rayConfig.reality_server_names || []).join(", "));
    } else {
      setV2rayFormEnabled(false);
      setV2rayFormProtocol("vless");
      setV2rayFormListenAddress("0.0.0.0");
      setV2rayFormPort(443);
      setV2rayFormTlsEnabled(true);
      setV2rayFormTlsCertPath("");
      setV2rayFormTlsKeyPath("");
      setV2rayFormTransportType("tcp");
      // Transport-specific config defaults
      setV2rayFormWsPath("/");
      setV2rayFormWsHost("");
      setV2rayFormGrpcServiceName("grpc");
      setV2rayFormGrpcAuthority("");
      setV2rayFormHttpHost("");
      setV2rayFormHttpPath("/");
      // XHTTP config defaults
      setV2rayFormXhttpPath("/");
      setV2rayFormXhttpMode("auto");
      setV2rayFormXhttpHost("");
      // Fallback config defaults
      setV2rayFormFallbackServer("");
      setV2rayFormFallbackPort(80);
      // XTLS/REALITY fields defaults
      setV2rayFormXtlsVision(false);
      setV2rayFormRealityEnabled(false);
      setV2rayFormRealityPrivateKey("");
      setV2rayFormRealityPublicKey("");
      setV2rayFormRealityShortIds("");
      setV2rayFormRealityDest("www.microsoft.com:443");
      setV2rayFormRealityServerNames("");
    }
    setShowV2rayConfigModal(true);
  };

  const handleSaveV2rayConfig = async () => {
    setActionLoading("save-v2ray-config");
    try {
      // Parse comma-separated fields to arrays
      const shortIds = v2rayFormRealityShortIds
        .split(",")
        .map(s => s.trim())
        .filter(s => s.length > 0);
      const serverNames = v2rayFormRealityServerNames
        .split(",")
        .map(s => s.trim())
        .filter(s => s.length > 0);

      // Build transport config based on transport type
      let transportConfig: Record<string, string> | undefined;
      if (v2rayFormTransportType === "ws") {
        transportConfig = { path: v2rayFormWsPath };
        if (v2rayFormWsHost) transportConfig.host = v2rayFormWsHost;
      } else if (v2rayFormTransportType === "grpc") {
        transportConfig = { service_name: v2rayFormGrpcServiceName };
        if (v2rayFormGrpcAuthority) transportConfig.authority = v2rayFormGrpcAuthority;
      } else if (v2rayFormTransportType === "h2") {
        transportConfig = { path: v2rayFormHttpPath };
        if (v2rayFormHttpHost) transportConfig.host = v2rayFormHttpHost;
      } else if (v2rayFormTransportType === "httpupgrade") {
        transportConfig = { path: v2rayFormWsPath };
        if (v2rayFormWsHost) transportConfig.host = v2rayFormWsHost;
      } else if (v2rayFormTransportType === "xhttp") {
        transportConfig = { path: v2rayFormXhttpPath };
        if (v2rayFormXhttpMode && v2rayFormXhttpMode !== "auto") transportConfig.mode = v2rayFormXhttpMode;
        if (v2rayFormXhttpHost) transportConfig.host = v2rayFormXhttpHost;
      }
      // QUIC uses default settings, no special config needed

      await api.updateV2RayInbound({
        protocol: v2rayFormProtocol,
        listen_address: v2rayFormListenAddress || "0.0.0.0",
        listen_port: v2rayFormPort,
        tls_enabled: v2rayFormTlsEnabled,
        tls_cert_path: v2rayFormTlsCertPath || undefined,
        tls_key_path: v2rayFormTlsKeyPath || undefined,
        transport_type: v2rayFormTransportType,
        transport_config: transportConfig,
        // Fallback config
        fallback_server: v2rayFormFallbackServer || undefined,
        fallback_port: v2rayFormFallbackServer ? v2rayFormFallbackPort : undefined,
        enabled: v2rayFormEnabled,
        // XTLS/REALITY fields
        xtls_vision_enabled: v2rayFormXtlsVision,
        reality_enabled: v2rayFormRealityEnabled,
        reality_private_key: v2rayFormRealityPrivateKey || undefined,
        reality_public_key: v2rayFormRealityPublicKey || undefined,
        reality_short_ids: shortIds.length > 0 ? shortIds : undefined,
        reality_dest: v2rayFormRealityDest || undefined,
        reality_server_names: serverNames.length > 0 ? serverNames : undefined
      });
      setSuccessMessage(t("v2rayIngress.configSaved"));
      setShowV2rayConfigModal(false);
      loadV2rayInbound();
      loadXrayStatus();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.saveFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleAddV2rayUser = async () => {
    if (!newV2rayUserName.trim()) return;

    setActionLoading("add-v2ray-user");
    try {
      await api.addV2RayUser({
        name: newV2rayUserName.trim(),
        email: newV2rayUserEmail.trim() || undefined
      });
      setSuccessMessage(t("v2rayIngress.userAdded", { name: newV2rayUserName }));
      setShowAddV2rayUserModal(false);
      setNewV2rayUserName("");
      setNewV2rayUserEmail("");
      loadV2rayInbound();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.createFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteV2rayUser = async (userId: number, userName: string) => {
    if (!confirm(t("v2rayIngress.confirmDeleteUser", { name: userName }))) return;

    setActionLoading(`delete-v2ray-user-${userId}`);
    try {
      await api.deleteV2RayUser(userId);
      setSuccessMessage(t("v2rayIngress.userDeleted", { name: userName }));
      loadV2rayInbound();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.deleteFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleShareV2rayUser = async (userId: number, userName: string) => {
    setActionLoading(`share-v2ray-user-${userId}`);
    try {
      const result = await api.getV2RayUserShareUri(userId);
      setShareUri(result.uri);
      setShareUriUser(userName);
      // 异步获取二维码 blob URL（带认证）
      const qrBlobUrl = await api.getV2RayUserQRCode(userId);
      setShareQrCodeUrl(qrBlobUrl);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("v2rayIngress.shareFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  // 关闭分享弹窗时清理 blob URL
  const handleCloseShareModal = () => {
    if (shareQrCodeUrl) {
      URL.revokeObjectURL(shareQrCodeUrl);
    }
    setShareUri(null);
    setShareUriUser(null);
    setShareQrCodeUrl(null);
  };

  // Generate random hex string for REALITY Short ID
  const generateRandomShortId = () => {
    const length = 8; // 8 hex chars = 4 bytes
    const array = new Uint8Array(length / 2);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  };

  const handleGenerateShortId = () => {
    const newId = generateRandomShortId();
    if (v2rayFormRealityShortIds.trim()) {
      // Append to existing IDs
      setV2rayFormRealityShortIds(v2rayFormRealityShortIds + ", " + newId);
    } else {
      setV2rayFormRealityShortIds(newId);
    }
  };

  const handleCopyShareUri = async () => {
    if (!shareUri) return;
    try {
      // 优先使用现代 Clipboard API
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(shareUri);
      } else {
        // 回退方案：使用临时 textarea 元素
        const textArea = document.createElement("textarea");
        textArea.value = shareUri;
        textArea.style.position = "fixed";
        textArea.style.left = "-9999px";
        textArea.style.top = "-9999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand("copy");
        document.body.removeChild(textArea);
        if (!successful) {
          throw new Error("execCommand failed");
        }
      }
      setSuccessMessage(t("v2rayIngress.uriCopied"));
      setTimeout(() => setSuccessMessage(null), 2000);
    } catch {
      setError(t("common.copyFailed"));
    }
  };

  // REALITY key generation
  const handleGenerateRealityKeys = async () => {
    setActionLoading("generate-reality-keys");
    try {
      const keyPair = await api.generateRealityKeys();
      setV2rayFormRealityPrivateKey(keyPair.private_key);
      setV2rayFormRealityPublicKey(keyPair.public_key);
      setSuccessMessage(t("v2rayIngress.realityKeysGenerated"));
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("v2rayIngress.realityKeysFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  // Xray control handlers
  const handleRestartXray = async () => {
    setActionLoading("restart-xray");
    try {
      const result = await api.restartXray();
      setXrayStatus(result.status);
      setSuccessMessage(t("v2rayIngress.xrayRestarted"));
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("v2rayIngress.xrayRestartFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  const handleReloadXray = async () => {
    setActionLoading("reload-xray");
    try {
      const result = await api.reloadXray();
      setXrayStatus(result.status);
      setSuccessMessage(t("v2rayIngress.xrayReloaded"));
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("v2rayIngress.xrayReloadFailed"));
    } finally {
      setActionLoading(null);
    }
  };

  if (v2rayLoading) {
    return (
      <div className="flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-violet-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{t("v2rayIngress.inbound")}</h1>
          <p className="text-slate-400 mt-1">{t("nav.v2rayIngressDesc")}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleOpenV2rayConfig}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
            title={t("ingress.settings")}
          >
            <Cog6ToothIcon className="h-5 w-5 text-slate-400" />
          </button>
          <button
            onClick={loadV2rayInbound}
            disabled={v2rayLoading}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors disabled:opacity-50"
            title={t("common.refresh")}
          >
            <ArrowPathIcon className={`h-5 w-5 text-slate-400 ${v2rayLoading ? "animate-spin" : ""}`} />
          </button>
          {v2rayConfig?.enabled === 1 && (
            <button
              onClick={() => setShowAddV2rayUserModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-600 text-white font-medium transition-colors"
            >
              <UserPlusIcon className="h-5 w-5" />
              {t("v2rayIngress.addUser")}
            </button>
          )}
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

      {/* Xray Status Bar */}
      {v2rayConfig?.enabled === 1 && xrayStatus && (
        <div className={`rounded-xl border p-4 ${
          xrayStatus.running
            ? "bg-emerald-500/10 border-emerald-500/20"
            : "bg-amber-500/10 border-amber-500/20"
        }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${
                xrayStatus.running ? "bg-emerald-500/20" : "bg-amber-500/20"
              }`}>
                <BoltIcon className={`h-5 w-5 ${
                  xrayStatus.running ? "text-emerald-400" : "text-amber-400"
                }`} />
              </div>
              <div>
                <p className="font-medium text-white">
                  Xray {xrayStatus.running ? t("common.running") : t("common.stopped")}
                </p>
                <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5">
                  {xrayStatus.tun_device && (
                    <span>TUN: {xrayStatus.tun_device}</span>
                  )}
                  {xrayStatus.reality_enabled && (
                    <span className="px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300">REALITY</span>
                  )}
                  {xrayStatus.xtls_vision_enabled && (
                    <span className="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300">XTLS-Vision</span>
                  )}
                  {xrayStatus.pid && (
                    <span>PID: {xrayStatus.pid}</span>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleReloadXray}
                disabled={actionLoading === "reload-xray"}
                className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white text-sm flex items-center gap-1.5 disabled:opacity-50"
                title={t("v2rayIngress.reloadXray")}
              >
                {actionLoading === "reload-xray" ? (
                  <ArrowPathIcon className="h-4 w-4 animate-spin" />
                ) : (
                  <ArrowPathIcon className="h-4 w-4" />
                )}
                {t("v2rayIngress.reload")}
              </button>
              <button
                onClick={handleRestartXray}
                disabled={actionLoading === "restart-xray"}
                className="px-3 py-1.5 rounded-lg bg-violet-500 hover:bg-violet-600 text-white text-sm flex items-center gap-1.5 disabled:opacity-50"
                title={t("v2rayIngress.restartXray")}
              >
                {actionLoading === "restart-xray" ? (
                  <ArrowPathIcon className="h-4 w-4 animate-spin" />
                ) : (
                  <SignalIcon className="h-4 w-4" />
                )}
                {t("v2rayIngress.restart")}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* V2Ray Content */}
      <div className="space-y-4">
        {!v2rayConfig || v2rayConfig.enabled === 0 ? (
          <div className="space-y-6">
            <div className="rounded-xl bg-white/5 border border-white/10 p-12 text-center">
              <ServerIcon className="h-12 w-12 text-slate-600 mx-auto mb-4" />
              <p className="text-slate-400 mb-4">{t("v2rayIngress.notEnabled")}</p>
              <button
                onClick={handleOpenV2rayConfig}
                className="px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-600 text-white text-sm font-medium"
              >
                {t("v2rayIngress.enableNow")}
              </button>
            </div>

            {/* Usage Guide */}
            <div className="rounded-xl bg-violet-500/5 border border-violet-500/20 p-5">
              <h3 className="text-xs font-semibold text-violet-300 mb-3">{t("v2rayIngress.usageGuide")}</h3>

              {/* Steps */}
              <ol className="space-y-2.5 text-xs text-slate-400">
                <li className="flex items-start gap-2.5">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-violet-500/20 text-violet-300 text-[10px] flex items-center justify-center font-medium">1</span>
                  <div>
                    <span className="text-slate-300 font-medium">{t("v2rayIngress.usageStep1Title")}</span>
                    <span className="text-slate-500"> - {t("v2rayIngress.usageStep1Desc")}</span>
                  </div>
                </li>
                <li className="flex items-start gap-2.5">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-violet-500/20 text-violet-300 text-[10px] flex items-center justify-center font-medium">2</span>
                  <div className="flex-1">
                    <span className="text-slate-300 font-medium">{t("v2rayIngress.usageStep2Title")}</span>
                    <span className="text-slate-500"> - {t("v2rayIngress.usageStep2Desc")}</span>
                    <ul className="mt-1.5 ml-2 space-y-1 text-slate-500">
                      <li className="flex items-start gap-1.5">
                        <span className="text-violet-400">•</span>
                        <span><span className="text-violet-300">{t("v2rayIngress.configOption1")}</span> - {t("v2rayIngress.configOption1Desc")}</span>
                      </li>
                      <li className="flex items-start gap-1.5">
                        <span className="text-violet-400">•</span>
                        <span><span className="text-violet-300">{t("v2rayIngress.configOption2")}</span> - {t("v2rayIngress.configOption2Desc")}</span>
                      </li>
                      <li className="flex items-start gap-1.5">
                        <span className="text-violet-400">•</span>
                        <span><span className="text-violet-300">{t("v2rayIngress.configOption3")}</span> - {t("v2rayIngress.configOption3Desc")}</span>
                      </li>
                      <li className="flex items-start gap-1.5">
                        <span className="text-violet-400">•</span>
                        <span><span className="text-violet-300">{t("v2rayIngress.configOption4")}</span> - {t("v2rayIngress.configOption4Desc")}</span>
                      </li>
                    </ul>
                  </div>
                </li>
                <li className="flex items-start gap-2.5">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-violet-500/20 text-violet-300 text-[10px] flex items-center justify-center font-medium">3</span>
                  <div>
                    <span className="text-slate-300 font-medium">{t("v2rayIngress.usageStep3Title")}</span>
                    <span className="text-slate-500"> - {t("v2rayIngress.usageStep3Desc")}</span>
                  </div>
                </li>
                <li className="flex items-start gap-2.5">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-violet-500/20 text-violet-300 text-[10px] flex items-center justify-center font-medium">4</span>
                  <div>
                    <span className="text-slate-300 font-medium">{t("v2rayIngress.usageStep4Title")}</span>
                    <span className="text-slate-500"> - {t("v2rayIngress.usageStep4Desc")}</span>
                  </div>
                </li>
              </ol>

              {/* Supported Clients */}
              <div className="mt-3 pt-3 border-t border-violet-500/10">
                <p className="text-[11px] text-slate-500">
                  <span className="text-slate-400">{t("v2rayIngress.supportedClients")}:</span> {t("v2rayIngress.clientList")}
                </p>
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* V2Ray Config Info */}
            <div className="rounded-xl bg-white/5 border border-white/10 p-4">
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 text-sm">
                <div>
                  <p className="text-xs text-slate-500">{t("v2rayIngress.protocol")}</p>
                  <p className="font-medium text-white">
                    {V2RAY_PROTOCOLS.find(p => p.value === v2rayConfig.protocol)?.label || v2rayConfig.protocol}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">{t("v2rayIngress.listenPort")}</p>
                  <p className="font-mono text-white">{v2rayConfig.listen_port}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">{t("v2rayIngress.transport")}</p>
                  <p className="text-white">
                    {V2RAY_TRANSPORTS.find(tr => tr.value === v2rayConfig.transport_type)?.label || v2rayConfig.transport_type}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">TLS</p>
                  <p className="text-white">{v2rayConfig.tls_enabled === 1 ? t("common.enabled") : t("common.disabled")}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">XTLS-Vision</p>
                  <p className={v2rayConfig.xtls_vision_enabled === 1 ? "text-cyan-400" : "text-slate-500"}>
                    {v2rayConfig.xtls_vision_enabled === 1 ? t("common.enabled") : t("common.disabled")}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">REALITY</p>
                  <p className={v2rayConfig.reality_enabled === 1 ? "text-violet-400" : "text-slate-500"}>
                    {v2rayConfig.reality_enabled === 1 ? t("common.enabled") : t("common.disabled")}
                  </p>
                </div>
              </div>
            </div>

            {/* V2Ray Users */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-slate-400">
                {t("v2rayIngress.addUser")} ({v2rayUsers.length})
              </h3>

              {v2rayUsers.length === 0 ? (
                <div className="rounded-xl bg-violet-500/5 border border-violet-500/20 p-6 text-center">
                  <p className="text-violet-300 mb-3">{t("v2rayIngress.noUsers")}</p>
                  <button
                    onClick={() => setShowAddV2rayUserModal(true)}
                    className="px-4 py-2 rounded-lg bg-violet-500 text-white text-sm font-medium"
                  >
                    {t("v2rayIngress.addFirstUser")}
                  </button>
                </div>
              ) : (
                <div className="grid gap-3 md:grid-cols-2">
                  {v2rayUsers.map(user => (
                    <div
                      key={user.id}
                      className="rounded-xl bg-violet-500/5 border border-violet-500/20 p-4"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-semibold text-white">{user.name}</h4>
                            <span
                              className={`w-2 h-2 rounded-full ${
                                userOnlineStatus[user.email || user.name]
                                  ? "bg-green-500"
                                  : "bg-slate-600"
                              }`}
                              title={userOnlineStatus[user.email || user.name] ? t("v2rayIngress.online") : t("v2rayIngress.offline")}
                            />
                          </div>
                          {user.email && <p className="text-xs text-slate-500">{user.email}</p>}
                          <p className="text-xs font-mono text-slate-400 mt-1 truncate" title={user.uuid}>
                            {user.uuid?.substring(0, 8)}...{user.uuid?.substring(user.uuid.length - 8)}
                          </p>
                        </div>
                        <div className="flex gap-1">
                          <button
                            onClick={() => handleShareV2rayUser(user.id, user.name)}
                            disabled={actionLoading === `share-v2ray-user-${user.id}`}
                            className="p-1.5 rounded-lg text-slate-400 hover:bg-white/10 hover:text-violet-400"
                            title={t("v2rayIngress.shareUri")}
                          >
                            {actionLoading === `share-v2ray-user-${user.id}` ? (
                              <ArrowPathIcon className="h-4 w-4 animate-spin" />
                            ) : (
                              <ShareIcon className="h-4 w-4" />
                            )}
                          </button>
                          <button
                            onClick={() => handleDeleteV2rayUser(user.id, user.name)}
                            disabled={actionLoading === `delete-v2ray-user-${user.id}`}
                            className="p-1.5 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                            title={t("common.delete")}
                          >
                            <TrashIcon className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* Share URI Modal */}
      {shareUri && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-bold text-white">
                    {t("v2rayIngress.shareUriTitle", { name: shareUriUser })}
                  </h2>
                  <button
                    onClick={handleCloseShareModal}
                    className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>
              <div className="p-6 space-y-4">
                {/* QR Code */}
                {shareQrCodeUrl && (
                  <div className="flex flex-col items-center gap-2">
                    <div className="p-4 bg-white rounded-xl">
                      <img
                        src={shareQrCodeUrl}
                        alt="QR Code"
                        className="w-48 h-48"
                      />
                    </div>
                    <p className="text-xs text-slate-500">{t("v2rayIngress.scanQrCode")}</p>
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("v2rayIngress.shareLink")}
                  </label>
                  <textarea
                    readOnly
                    value={shareUri}
                    className="w-full h-24 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-xs resize-none"
                  />
                </div>
                <div className="flex justify-end gap-3">
                  <button
                    onClick={handleCloseShareModal}
                    className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white text-sm"
                  >
                    {t("common.close")}
                  </button>
                  <button
                    onClick={handleCopyShareUri}
                    className="px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-600 text-white text-sm font-medium flex items-center gap-2"
                  >
                    <ClipboardDocumentIcon className="h-4 w-4" />
                    {t("v2rayIngress.copyUri")}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* V2Ray Config Modal */}
      {showV2rayConfigModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-bold text-white">{t("v2rayIngress.configTitle")}</h2>
                  <button
                    onClick={() => setShowV2rayConfigModal(false)}
                    className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>
              <div className="p-6 space-y-4">
                {/* Enable Toggle */}
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-white">{t("v2rayIngress.enableInbound")}</span>
                  <button
                    onClick={() => setV2rayFormEnabled(!v2rayFormEnabled)}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                      v2rayFormEnabled ? "bg-violet-500" : "bg-slate-700"
                    }`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                        v2rayFormEnabled ? "translate-x-6" : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>
                {/* Protocol */}
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("v2rayIngress.protocol")}
                  </label>
                  <div className="flex gap-2">
                    {V2RAY_PROTOCOLS.map(p => (
                      <button
                        key={p.value}
                        onClick={() => setV2rayFormProtocol(p.value)}
                        className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                          v2rayFormProtocol === p.value
                            ? "bg-violet-500 text-white"
                            : "bg-white/5 text-slate-400 hover:text-white"
                        }`}
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                </div>
                {/* Listen Address */}
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("v2rayIngress.listenAddress")}
                  </label>
                  <input
                    type="text"
                    value={v2rayFormListenAddress}
                    onChange={(e) => setV2rayFormListenAddress(e.target.value)}
                    placeholder="0.0.0.0"
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-sm focus:outline-none focus:border-violet-500"
                  />
                  <p className="text-xs text-slate-500 mt-1">{t("v2rayIngress.listenAddressHint")}</p>
                </div>
                {/* Port */}
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("v2rayIngress.listenPort")}
                  </label>
                  <input
                    type="number"
                    value={v2rayFormPort}
                    onChange={(e) => setV2rayFormPort(parseInt(e.target.value) || 443)}
                    min={1}
                    max={65535}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-violet-500"
                  />
                </div>
                {/* TLS Toggle */}
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-white">TLS</span>
                  <button
                    onClick={() => setV2rayFormTlsEnabled(!v2rayFormTlsEnabled)}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                      v2rayFormTlsEnabled ? "bg-violet-500" : "bg-slate-700"
                    }`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                        v2rayFormTlsEnabled ? "translate-x-6" : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>

                {/* TLS Certificate Config (when TLS enabled and REALITY disabled) */}
                {v2rayFormTlsEnabled && !v2rayFormRealityEnabled && (
                  <div className="space-y-3 p-3 rounded-lg bg-white/5 border border-white/10">
                    <h4 className="text-xs font-semibold text-slate-400">{t("v2rayIngress.tlsCertConfig")}</h4>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.tlsCertPath")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormTlsCertPath}
                        onChange={(e) => setV2rayFormTlsCertPath(e.target.value)}
                        placeholder="/etc/ssl/certs/cert.pem"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-violet-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.tlsKeyPath")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormTlsKeyPath}
                        onChange={(e) => setV2rayFormTlsKeyPath(e.target.value)}
                        placeholder="/etc/ssl/private/key.pem"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-violet-500"
                      />
                    </div>
                    <p className="text-xs text-slate-500">{t("v2rayIngress.tlsCertHint")}</p>
                  </div>
                )}

                {/* Transport */}
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("v2rayIngress.transport")}
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {V2RAY_TRANSPORTS.map(tr => (
                      <button
                        key={tr.value}
                        onClick={() => {
                          setV2rayFormTransportType(tr.value);
                          // XTLS-Vision only works with TCP transport
                          if (tr.value !== "tcp") {
                            setV2rayFormXtlsVision(false);
                          }
                        }}
                        className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${
                          v2rayFormTransportType === tr.value
                            ? "bg-violet-500 text-white"
                            : "bg-white/5 text-slate-400 hover:text-white"
                        }`}
                      >
                        {tr.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* WebSocket Config */}
                {v2rayFormTransportType === "ws" && (
                  <div className="space-y-3 p-3 rounded-lg bg-blue-500/5 border border-blue-500/20">
                    <h4 className="text-xs font-semibold text-blue-300">WebSocket {t("v2rayIngress.transportConfig")}</h4>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.wsPath")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormWsPath}
                        onChange={(e) => setV2rayFormWsPath(e.target.value)}
                        placeholder="/"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.wsHost")} ({t("common.optional")})
                      </label>
                      <input
                        type="text"
                        value={v2rayFormWsHost}
                        onChange={(e) => setV2rayFormWsHost(e.target.value)}
                        placeholder="example.com"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  </div>
                )}

                {/* gRPC Config */}
                {v2rayFormTransportType === "grpc" && (
                  <div className="space-y-3 p-3 rounded-lg bg-green-500/5 border border-green-500/20">
                    <h4 className="text-xs font-semibold text-green-300">gRPC {t("v2rayIngress.transportConfig")}</h4>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.grpcServiceName")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormGrpcServiceName}
                        onChange={(e) => setV2rayFormGrpcServiceName(e.target.value)}
                        placeholder="grpc"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-green-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.grpcAuthority")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormGrpcAuthority}
                        onChange={(e) => setV2rayFormGrpcAuthority(e.target.value)}
                        placeholder={t("v2rayIngress.grpcAuthorityPlaceholder")}
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-green-500"
                      />
                      <p className="mt-1 text-xs text-slate-500">{t("v2rayIngress.grpcAuthorityHint")}</p>
                    </div>
                  </div>
                )}

                {/* HTTP/2 Config */}
                {v2rayFormTransportType === "h2" && (
                  <div className="space-y-3 p-3 rounded-lg bg-orange-500/5 border border-orange-500/20">
                    <h4 className="text-xs font-semibold text-orange-300">HTTP/2 {t("v2rayIngress.transportConfig")}</h4>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.httpPath")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormHttpPath}
                        onChange={(e) => setV2rayFormHttpPath(e.target.value)}
                        placeholder="/"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-orange-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.httpHost")} ({t("common.optional")})
                      </label>
                      <input
                        type="text"
                        value={v2rayFormHttpHost}
                        onChange={(e) => setV2rayFormHttpHost(e.target.value)}
                        placeholder="example.com"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-orange-500"
                      />
                    </div>
                  </div>
                )}

                {/* QUIC Config */}
                {v2rayFormTransportType === "quic" && (
                  <div className="space-y-3 p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
                    <h4 className="text-xs font-semibold text-cyan-300">QUIC {t("v2rayIngress.transportConfig")}</h4>
                    <p className="text-xs text-slate-500">{t("v2rayIngress.quicNote")}</p>
                  </div>
                )}

                {/* HTTPUpgrade Config */}
                {v2rayFormTransportType === "httpupgrade" && (
                  <div className="space-y-3 p-3 rounded-lg bg-pink-500/5 border border-pink-500/20">
                    <h4 className="text-xs font-semibold text-pink-300">HTTPUpgrade {t("v2rayIngress.transportConfig")}</h4>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.wsPath")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormWsPath}
                        onChange={(e) => setV2rayFormWsPath(e.target.value)}
                        placeholder="/"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-pink-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.wsHost")} ({t("common.optional")})
                      </label>
                      <input
                        type="text"
                        value={v2rayFormWsHost}
                        onChange={(e) => setV2rayFormWsHost(e.target.value)}
                        placeholder="example.com"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-pink-500"
                      />
                    </div>
                  </div>
                )}

                {/* XHTTP Config */}
                {v2rayFormTransportType === "xhttp" && (
                  <div className="space-y-3 p-3 rounded-lg bg-indigo-500/5 border border-indigo-500/20">
                    <h4 className="text-xs font-semibold text-indigo-300">XHTTP {t("v2rayIngress.transportConfig")}</h4>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.xhttpPath")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormXhttpPath}
                        onChange={(e) => setV2rayFormXhttpPath(e.target.value)}
                        placeholder="/"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.xhttpMode")}
                      </label>
                      <div className="flex flex-wrap gap-2">
                        {(["auto", "packet-up", "stream-up", "stream-one"] as const).map(mode => (
                          <button
                            key={mode}
                            type="button"
                            onClick={() => setV2rayFormXhttpMode(mode)}
                            className={`px-2.5 py-1 rounded-lg text-xs transition-colors ${
                              v2rayFormXhttpMode === mode
                                ? "bg-indigo-500 text-white"
                                : "bg-white/5 text-slate-400 hover:text-white"
                            }`}
                          >
                            {mode}
                          </button>
                        ))}
                      </div>
                      <p className="text-xs text-slate-500 mt-1">{t("v2rayIngress.xhttpModeHint")}</p>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-500 mb-1">
                        {t("v2rayIngress.xhttpHost")} ({t("common.optional")})
                      </label>
                      <input
                        type="text"
                        value={v2rayFormXhttpHost}
                        onChange={(e) => setV2rayFormXhttpHost(e.target.value)}
                        placeholder="example.com"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </div>
                )}

                {/* Fallback Config (VLESS/Trojan only) */}
                {(v2rayFormProtocol === "vless" || v2rayFormProtocol === "trojan") && (
                  <div className="space-y-3 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                    <h4 className="text-xs font-semibold text-amber-300">{t("v2rayIngress.fallbackConfig")}</h4>
                    <p className="text-xs text-slate-500">{t("v2rayIngress.fallbackHint")}</p>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs font-medium text-slate-500 mb-1">
                          {t("v2rayIngress.fallbackServer")}
                        </label>
                        <input
                          type="text"
                          value={v2rayFormFallbackServer}
                          onChange={(e) => setV2rayFormFallbackServer(e.target.value)}
                          placeholder="127.0.0.1"
                          className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-amber-500"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-500 mb-1">
                          {t("v2rayIngress.fallbackPort")}
                        </label>
                        <input
                          type="number"
                          value={v2rayFormFallbackPort}
                          onChange={(e) => setV2rayFormFallbackPort(parseInt(e.target.value) || 80)}
                          min={1}
                          max={65535}
                          className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-amber-500"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* XTLS-Vision Toggle (VLESS + TCP only) */}
                {v2rayFormProtocol === "vless" && (
                  <div className="flex items-center justify-between">
                    <div>
                      <span className={`text-sm font-medium ${v2rayFormTransportType === "tcp" ? "text-white" : "text-slate-500"}`}>XTLS-Vision</span>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {v2rayFormTransportType === "tcp"
                          ? t("v2rayIngress.xtlsVisionDesc")
                          : t("v2rayIngress.xtlsVisionTcpOnly")}
                      </p>
                    </div>
                    <button
                      onClick={() => v2rayFormTransportType === "tcp" && setV2rayFormXtlsVision(!v2rayFormXtlsVision)}
                      disabled={v2rayFormTransportType !== "tcp"}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        v2rayFormXtlsVision && v2rayFormTransportType === "tcp"
                          ? "bg-cyan-500"
                          : v2rayFormTransportType !== "tcp"
                            ? "bg-slate-800 cursor-not-allowed opacity-50"
                            : "bg-slate-700"
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          v2rayFormXtlsVision && v2rayFormTransportType === "tcp" ? "translate-x-6" : "translate-x-1"
                        }`}
                      />
                    </button>
                  </div>
                )}

                {/* REALITY Toggle (VLESS only) */}
                {v2rayFormProtocol === "vless" && (
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-medium text-white">REALITY</span>
                      <p className="text-xs text-slate-500 mt-0.5">{t("v2rayIngress.realityDesc")}</p>
                    </div>
                    <button
                      onClick={() => setV2rayFormRealityEnabled(!v2rayFormRealityEnabled)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        v2rayFormRealityEnabled ? "bg-violet-500" : "bg-slate-700"
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          v2rayFormRealityEnabled ? "translate-x-6" : "translate-x-1"
                        }`}
                      />
                    </button>
                  </div>
                )}

                {/* REALITY Configuration (when enabled) */}
                {v2rayFormProtocol === "vless" && v2rayFormRealityEnabled && (
                  <div className="space-y-4 p-4 rounded-xl bg-violet-500/5 border border-violet-500/20">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-semibold text-violet-300">{t("v2rayIngress.realityConfig")}</h4>
                      <button
                        onClick={handleGenerateRealityKeys}
                        disabled={actionLoading === "generate-reality-keys"}
                        className="px-3 py-1 rounded-lg bg-violet-500/20 hover:bg-violet-500/30 text-violet-300 text-xs flex items-center gap-1.5"
                      >
                        {actionLoading === "generate-reality-keys" ? (
                          <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <KeyIcon className="h-3.5 w-3.5" />
                        )}
                        {t("v2rayIngress.generateKeys")}
                      </button>
                    </div>

                    {/* Private Key */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {t("v2rayIngress.realityPrivateKey")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormRealityPrivateKey}
                        onChange={(e) => setV2rayFormRealityPrivateKey(e.target.value)}
                        placeholder={t("v2rayIngress.clickGenerateKeys")}
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-xs focus:outline-none focus:border-violet-500"
                      />
                    </div>

                    {/* Public Key (for client) */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {t("v2rayIngress.realityPublicKey")} ({t("v2rayIngress.forClient")})
                      </label>
                      <input
                        type="text"
                        value={v2rayFormRealityPublicKey}
                        readOnly
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-slate-400 font-mono text-xs"
                      />
                    </div>

                    {/* Dest Server */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {t("v2rayIngress.realityDest")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormRealityDest}
                        onChange={(e) => setV2rayFormRealityDest(e.target.value)}
                        placeholder="www.microsoft.com:443"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-violet-500"
                      />
                    </div>

                    {/* Server Names */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {t("v2rayIngress.realityServerNames")}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormRealityServerNames}
                        onChange={(e) => setV2rayFormRealityServerNames(e.target.value)}
                        placeholder="www.microsoft.com, microsoft.com"
                        className="w-full px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white text-xs focus:outline-none focus:border-violet-500"
                      />
                      <p className="text-xs text-slate-500 mt-1">{t("v2rayIngress.commaSeparated")}</p>
                    </div>

                    {/* Short IDs */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {t("v2rayIngress.realityShortIds")}
                      </label>
                      <div className="flex gap-2">
                        <input
                          type="text"
                          value={v2rayFormRealityShortIds}
                          onChange={(e) => setV2rayFormRealityShortIds(e.target.value)}
                          placeholder="abc123, def456"
                          className="flex-1 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-xs focus:outline-none focus:border-violet-500"
                        />
                        <button
                          type="button"
                          onClick={handleGenerateShortId}
                          className="px-3 py-1.5 rounded-lg bg-violet-500/20 hover:bg-violet-500/30 text-violet-300 text-xs font-medium whitespace-nowrap"
                          title={t("v2rayIngress.generateShortId")}
                        >
                          {t("v2rayIngress.random")}
                        </button>
                      </div>
                      <p className="text-xs text-slate-500 mt-1">{t("v2rayIngress.shortIdsDesc")}</p>
                    </div>
                  </div>
                )}
              </div>
              <div className="p-6 border-t border-white/10 flex justify-end gap-3">
                <button
                  onClick={() => setShowV2rayConfigModal(false)}
                  className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white text-sm"
                >
                  {t("common.cancel")}
                </button>
                <button
                  onClick={handleSaveV2rayConfig}
                  disabled={actionLoading === "save-v2ray-config"}
                  className="px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-600 text-white text-sm font-medium flex items-center gap-2 disabled:opacity-50"
                >
                  {actionLoading === "save-v2ray-config" ? (
                    <ArrowPathIcon className="h-4 w-4 animate-spin" />
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

      {/* Add V2Ray User Modal */}
      {showAddV2rayUserModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-md">
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-bold text-white">{t("v2rayIngress.addUser")}</h2>
                  <button
                    onClick={() => { setShowAddV2rayUserModal(false); setNewV2rayUserName(""); setNewV2rayUserEmail(""); }}
                    className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>
              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("v2rayIngress.userName")} <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    value={newV2rayUserName}
                    onChange={(e) => setNewV2rayUserName(e.target.value)}
                    placeholder={t("v2rayIngress.userNamePlaceholder")}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t("v2rayIngress.userEmail")} ({t("common.optional")})
                  </label>
                  <input
                    type="email"
                    value={newV2rayUserEmail}
                    onChange={(e) => setNewV2rayUserEmail(e.target.value)}
                    placeholder="user@example.com"
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                  />
                </div>
                <p className="text-xs text-slate-500">{t("v2rayIngress.uuidAutoGenerate")}</p>
              </div>
              <div className="p-6 border-t border-white/10 flex justify-end gap-3">
                <button
                  onClick={() => { setShowAddV2rayUserModal(false); setNewV2rayUserName(""); setNewV2rayUserEmail(""); }}
                  className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white text-sm"
                >
                  {t("common.cancel")}
                </button>
                <button
                  onClick={handleAddV2rayUser}
                  disabled={!newV2rayUserName.trim() || actionLoading === "add-v2ray-user"}
                  className="px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-600 text-white text-sm font-medium flex items-center gap-2 disabled:opacity-50"
                >
                  {actionLoading === "add-v2ray-user" ? (
                    <ArrowPathIcon className="h-4 w-4 animate-spin" />
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
    </div>
  );
}
