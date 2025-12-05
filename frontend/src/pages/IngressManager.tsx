import { useState, useEffect, useCallback } from "react";
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

function formatLastSeen(timestamp: number): string {
  if (timestamp === 0) return "从未连接";
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestamp;
  if (diff < 60) return "刚刚";
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;
  return `${Math.floor(diff / 86400)} 天前`;
}

export default function IngressManager() {
  const [ingress, setIngress] = useState<IngressResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Add peer modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [newPeerName, setNewPeerName] = useState("");
  const [newPeerPublicKey, setNewPeerPublicKey] = useState("");
  const [useCustomKey, setUseCustomKey] = useState(false);

  // Config modal (shows after adding peer or for existing peer)
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [configPeerName, setConfigPeerName] = useState("");
  const [configPrivateKey, setConfigPrivateKey] = useState("");
  const [configCopied, setConfigCopied] = useState(false);

  // Settings
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [serverEndpoint, setServerEndpoint] = useState("");
  const [serverEndpointSaved, setServerEndpointSaved] = useState("");
  const [savingSettings, setSavingSettings] = useState(false);

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
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadIngress();
    loadSettings();
    // 自动刷新状态（每 30 秒）
    const interval = setInterval(loadIngress, 30000);
    return () => clearInterval(interval);
  }, [loadIngress, loadSettings]);

  const handleSaveSettings = async () => {
    setSavingSettings(true);
    try {
      await api.updateSettings(serverEndpoint.trim());
      setServerEndpointSaved(serverEndpoint.trim());
      setSuccessMessage("服务器地址已保存");
      setShowSettingsModal(false);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "保存失败");
    } finally {
      setSavingSettings(false);
    }
  };

  const handleAddPeer = async () => {
    if (!newPeerName.trim()) {
      setError("请输入客户端名称");
      return;
    }

    setActionLoading("add");
    try {
      const result = await api.addIngressPeer(
        newPeerName.trim(),
        useCustomKey ? newPeerPublicKey.trim() : undefined
      );
      setSuccessMessage(result.message);
      setShowAddModal(false);
      setNewPeerName("");
      setNewPeerPublicKey("");
      setUseCustomKey(false);

      // 如果服务端生成了私钥，显示配置
      if (result.client_private_key) {
        setConfigPeerName(newPeerName.trim());
        setConfigPrivateKey(result.client_private_key);
        setShowConfigModal(true);
      }

      loadIngress();
      setTimeout(() => setSuccessMessage(null), 5000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "添加失败");
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeletePeer = async (name: string) => {
    if (!confirm(`确定要删除客户端 "${name}" 吗？`)) return;

    setActionLoading(`delete-${name}`);
    try {
      await api.deleteIngressPeer(name);
      setSuccessMessage(`客户端 "${name}" 已删除`);
      loadIngress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "删除失败");
    } finally {
      setActionLoading(null);
    }
  };

  const handleShowConfig = (peer: IngressPeer) => {
    setConfigPeerName(peer.name);
    setConfigPrivateKey("");
    setShowConfigModal(true);
  };

  const handleCopyConfig = async () => {
    const configUrl = api.getIngressPeerConfigUrl(configPeerName, configPrivateKey || undefined);
    try {
      const response = await fetch(configUrl);
      const text = await response.text();
      await navigator.clipboard.writeText(text);
      setConfigCopied(true);
      setTimeout(() => setConfigCopied(false), 2000);
    } catch {
      setError("复制失败");
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
          <h1 className="text-2xl font-bold text-white">客户端管理</h1>
          <p className="text-slate-400 mt-1">管理连接到网关的 WireGuard 客户端</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowSettingsModal(true)}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
            title="设置"
          >
            <Cog6ToothIcon className="h-5 w-5 text-slate-400" />
          </button>
          <button
            onClick={loadIngress}
            disabled={loading}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors disabled:opacity-50"
            title="刷新"
          >
            <ArrowPathIcon className={`h-5 w-5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white font-medium transition-colors"
          >
            <PlusIcon className="h-5 w-5" />
            添加客户端
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
          <h3 className="text-sm font-semibold text-slate-400 mb-3">入口接口</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-xs text-slate-500">接口名称</p>
              <p className="font-mono text-white">{ingress.interface.name}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">监听端口</p>
              <p className="font-mono text-white">{ingress.interface.listen_port}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">地址</p>
              <p className="font-mono text-white">{ingress.interface.address}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">MTU</p>
              <p className="font-mono text-white">{ingress.interface.mtu}</p>
            </div>
          </div>
          {ingress.interface.public_key && (
            <div className="mt-3 pt-3 border-t border-white/5">
              <p className="text-xs text-slate-500 mb-1">服务端公钥</p>
              <p className="font-mono text-xs text-slate-300 break-all">{ingress.interface.public_key}</p>
            </div>
          )}
        </div>
      )}

      {/* Peers List */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-400">
          已连接客户端 ({ingress?.peer_count || 0})
        </h3>

        {ingress?.peers.length === 0 ? (
          <div className="rounded-xl bg-white/5 border border-white/10 p-12 text-center">
            <WifiIcon className="h-12 w-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">还没有添加任何客户端</p>
            <button
              onClick={() => setShowAddModal(true)}
              className="mt-4 px-4 py-2 rounded-lg bg-brand text-white text-sm font-medium"
            >
              添加第一个客户端
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
                        title="获取配置"
                      >
                        <QrCodeIcon className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDeletePeer(peer.name)}
                        disabled={actionLoading === `delete-${peer.name}`}
                        className="p-2 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                        title="删除"
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t border-white/5 grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <p className="text-slate-500">状态</p>
                      <p className={peer.is_online ? "text-emerald-400" : "text-slate-400"}>
                        {peer.is_online ? "在线" : "离线"}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500">最后活跃</p>
                      <p className="text-slate-300">{formatLastSeen(peer.last_handshake)}</p>
                    </div>
                    <div>
                      <p className="text-slate-500">流量</p>
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
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-md">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">添加客户端</h2>
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
                  客户端名称 <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={newPeerName}
                  onChange={(e) => setNewPeerName(e.target.value)}
                  placeholder="例如: laptop, phone, tablet"
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useCustomKey}
                    onChange={(e) => setUseCustomKey(e.target.checked)}
                    className="rounded border-slate-600"
                  />
                  使用自定义公钥（高级）
                </label>
              </div>

              {useCustomKey && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    客户端公钥
                  </label>
                  <input
                    type="text"
                    value={newPeerPublicKey}
                    onChange={(e) => setNewPeerPublicKey(e.target.value)}
                    placeholder="Base64 编码的 WireGuard 公钥"
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-sm placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    如果您已有密钥对，可在此填入公钥
                  </p>
                </div>
              )}

              {!useCustomKey && (
                <div className="rounded-lg bg-blue-500/10 border border-blue-500/20 p-3">
                  <p className="text-xs text-blue-300">
                    服务端将自动生成密钥对，添加后会显示配置文件和二维码
                  </p>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                取消
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
                添加
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Config Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">客户端配置 - {configPeerName}</h2>
                <button
                  onClick={() => {
                    setShowConfigModal(false);
                    setConfigPrivateKey("");
                  }}
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
                    如果您有客户端私钥，请输入以生成完整配置；否则配置中的私钥将显示为占位符
                  </p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  客户端私钥（可选）
                </label>
                <input
                  type="text"
                  value={configPrivateKey}
                  onChange={(e) => setConfigPrivateKey(e.target.value)}
                  placeholder="添加时生成的私钥"
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-sm placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              {/* QR Code */}
              <div className="flex justify-center py-4">
                <div className="bg-white p-2 rounded-lg">
                  <img
                    src={api.getIngressPeerQrcodeUrl(configPeerName, configPrivateKey || undefined)}
                    alt="WireGuard 配置二维码"
                    className="w-48 h-48"
                    onError={(e) => {
                      (e.target as HTMLImageElement).style.display = "none";
                    }}
                  />
                </div>
              </div>

              <p className="text-xs text-slate-500 text-center">
                使用 WireGuard 客户端扫描二维码快速导入配置
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
                    已复制
                  </>
                ) : (
                  <>
                    <ClipboardDocumentIcon className="h-4 w-4" />
                    复制配置
                  </>
                )}
              </button>
              <button
                onClick={handleDownloadConfig}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors"
              >
                <ArrowDownTrayIcon className="h-4 w-4" />
                下载 .conf 文件
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Settings Modal */}
      {showSettingsModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-md">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">入口设置</h2>
                <button
                  onClick={() => {
                    setShowSettingsModal(false);
                    setServerEndpoint(serverEndpointSaved);
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
                  服务器公网地址 <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={serverEndpoint}
                  onChange={(e) => setServerEndpoint(e.target.value)}
                  placeholder="例如: 1.2.3.4 或 vpn.example.com"
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
                <p className="text-xs text-slate-500 mt-2">
                  客户端将通过此地址连接到服务器，请确保端口 {ingress?.interface.listen_port || 36100} 已开放
                </p>
              </div>

              {!serverEndpointSaved && (
                <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-3">
                  <p className="text-xs text-amber-300">
                    未设置服务器地址，生成的客户端配置将显示占位符
                  </p>
                </div>
              )}

              {serverEndpointSaved && (
                <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-3">
                  <p className="text-xs text-emerald-300">
                    当前服务器地址: {serverEndpointSaved}:{ingress?.interface.listen_port || 36100}
                  </p>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowSettingsModal(false);
                  setServerEndpoint(serverEndpointSaved);
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                取消
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
                保存
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
