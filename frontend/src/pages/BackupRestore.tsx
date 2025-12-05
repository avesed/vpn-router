import { useState, useEffect, useRef } from "react";
import { api } from "../api/client";
import type { BackupStatus } from "../types";
import {
  ArrowDownTrayIcon,
  ArrowUpTrayIcon,
  ArrowPathIcon,
  ShieldCheckIcon,
  CheckCircleIcon,
  XCircleIcon,
  EyeIcon,
  EyeSlashIcon,
  DocumentTextIcon
} from "@heroicons/react/24/outline";

export default function BackupRestore() {
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Export state
  const [exportPassword, setExportPassword] = useState("");
  const [showExportPassword, setShowExportPassword] = useState(false);
  const [includePiaCredentials, setIncludePiaCredentials] = useState(true);
  const [exporting, setExporting] = useState(false);

  // Import state
  const [importPassword, setImportPassword] = useState("");
  const [showImportPassword, setShowImportPassword] = useState(false);
  const [mergeMode, setMergeMode] = useState<"replace" | "merge">("replace");
  const [importing, setImporting] = useState(false);
  const [importData, setImportData] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadStatus = async () => {
    try {
      setLoading(true);
      const data = await api.getBackupStatus();
      setStatus(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载状态失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  const handleExport = async () => {
    setExporting(true);
    setError(null);
    try {
      const result = await api.exportBackup(
        exportPassword || undefined,
        includePiaCredentials
      );

      // Download as JSON file
      const blob = new Blob([JSON.stringify(result.backup, null, 2)], {
        type: "application/json"
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const timestamp = new Date().toISOString().slice(0, 10);
      a.download = `vpn-gateway-backup-${timestamp}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setSuccessMessage(
        result.encrypted
          ? "备份已导出（已加密）"
          : "备份已导出（未加密，敏感数据可见）"
      );
      setExportPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "导出失败");
    } finally {
      setExporting(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const content = await file.text();
      setImportData(content);
      // Validate JSON
      JSON.parse(content);
      setError(null);
    } catch {
      setError("无效的备份文件格式");
      setImportData("");
    }
  };

  const handleImport = async () => {
    if (!importData) {
      setError("请先选择备份文件");
      return;
    }

    setImporting(true);
    setError(null);
    try {
      const result = await api.importBackup(
        importData,
        importPassword || undefined,
        mergeMode
      );

      const imported = Object.entries(result.results)
        .filter(([, v]) => v)
        .map(([k]) => {
          const names: Record<string, string> = {
            settings: "设置",
            ingress: "入口配置",
            custom_egress: "自定义出口",
            pia_profiles: "PIA 线路",
            pia_credentials: "PIA 凭证",
            custom_rules: "路由规则"
          };
          return names[k] || k;
        });

      setSuccessMessage(`已导入: ${imported.join(", ")}`);
      setImportData("");
      setImportPassword("");
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
      loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "导入失败");
    } finally {
      setImporting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="h-10 w-10 animate-spin rounded-full border-4 border-slate-700 border-t-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">备份与恢复</h1>
          <p className="text-slate-400 mt-1">
            导出配置以便迁移或备份，导入配置以恢复设置
          </p>
        </div>
        <button
          onClick={loadStatus}
          disabled={loading}
          className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
          title="刷新"
        >
          <ArrowPathIcon
            className={`h-5 w-5 text-slate-400 ${loading ? "animate-spin" : ""}`}
          />
        </button>
      </div>

      {/* Messages */}
      {error && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-4 text-red-400">
          {error}
        </div>
      )}
      {successMessage && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/20 p-4 text-emerald-400 flex items-center gap-2">
          <CheckCircleIcon className="h-5 w-5" />
          {successMessage}
        </div>
      )}

      {/* Current Status */}
      {status && (
        <div className="rounded-xl bg-white/5 border border-white/10 p-5">
          <h3 className="text-sm font-semibold text-slate-400 mb-3 flex items-center gap-2">
            <DocumentTextIcon className="h-4 w-4" />
            当前配置概览
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 rounded-lg bg-white/5">
              <p className="text-2xl font-bold text-white">
                {status.ingress_peer_count}
              </p>
              <p className="text-xs text-slate-400">入口客户端</p>
            </div>
            <div className="text-center p-3 rounded-lg bg-white/5">
              <p className="text-2xl font-bold text-white">
                {status.custom_egress_count}
              </p>
              <p className="text-xs text-slate-400">自定义出口</p>
            </div>
            <div className="text-center p-3 rounded-lg bg-white/5">
              <p className="text-2xl font-bold text-white">
                {status.pia_profile_count}
              </p>
              <p className="text-xs text-slate-400">PIA 线路</p>
            </div>
            <div className="text-center p-3 rounded-lg bg-white/5">
              <div className="flex justify-center">
                {status.has_pia_credentials ? (
                  <CheckCircleIcon className="h-6 w-6 text-emerald-400" />
                ) : (
                  <XCircleIcon className="h-6 w-6 text-slate-500" />
                )}
              </div>
              <p className="text-xs text-slate-400">PIA 凭证</p>
            </div>
          </div>
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-6">
        {/* Export Section */}
        <div className="rounded-xl bg-white/5 border border-white/10 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-blue-500/20">
              <ArrowDownTrayIcon className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <h3 className="font-semibold text-white">导出配置</h3>
              <p className="text-xs text-slate-400">生成备份文件</p>
            </div>
          </div>

          <div className="space-y-4">
            {/* Encryption Password */}
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                加密密码（可选）
              </label>
              <div className="relative">
                <input
                  type={showExportPassword ? "text" : "password"}
                  value={exportPassword}
                  onChange={(e) => setExportPassword(e.target.value)}
                  placeholder="留空则不加密敏感数据"
                  className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 pr-10 text-sm text-white"
                />
                <button
                  type="button"
                  onClick={() => setShowExportPassword(!showExportPassword)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                >
                  {showExportPassword ? (
                    <EyeSlashIcon className="h-4 w-4" />
                  ) : (
                    <EyeIcon className="h-4 w-4" />
                  )}
                </button>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                设置密码后，私钥和凭证将使用 AES-256 加密
              </p>
            </div>

            {/* Include PIA Credentials */}
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={includePiaCredentials}
                onChange={(e) => setIncludePiaCredentials(e.target.checked)}
                className="rounded border-white/20 bg-slate-900 text-brand focus:ring-brand"
              />
              <span className="text-sm text-slate-300">包含 PIA 账户凭证</span>
            </label>

            {/* Warning if no password */}
            {!exportPassword && (
              <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-3">
                <p className="text-xs text-amber-400">
                  <ShieldCheckIcon className="h-4 w-4 inline mr-1" />
                  未设置密码时，私钥和凭证将以明文保存，请妥善保管备份文件
                </p>
              </div>
            )}

            <button
              onClick={handleExport}
              disabled={exporting}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-blue-500 hover:bg-blue-600 text-white font-medium transition-colors disabled:opacity-50"
            >
              {exporting ? (
                <>
                  <ArrowPathIcon className="h-4 w-4 animate-spin" />
                  导出中...
                </>
              ) : (
                <>
                  <ArrowDownTrayIcon className="h-4 w-4" />
                  导出备份
                </>
              )}
            </button>
          </div>
        </div>

        {/* Import Section */}
        <div className="rounded-xl bg-white/5 border border-white/10 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-emerald-500/20">
              <ArrowUpTrayIcon className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <h3 className="font-semibold text-white">导入配置</h3>
              <p className="text-xs text-slate-400">从备份文件恢复</p>
            </div>
          </div>

          <div className="space-y-4">
            {/* File Upload */}
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                选择备份文件
              </label>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json"
                onChange={handleFileUpload}
                className="w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-white/10 file:text-white hover:file:bg-white/20"
              />
              {importData && (
                <p className="text-xs text-emerald-400 mt-1">
                  <CheckCircleIcon className="h-3 w-3 inline mr-1" />
                  已加载备份文件
                </p>
              )}
            </div>

            {/* Decryption Password */}
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                解密密码
              </label>
              <div className="relative">
                <input
                  type={showImportPassword ? "text" : "password"}
                  value={importPassword}
                  onChange={(e) => setImportPassword(e.target.value)}
                  placeholder="如果备份已加密，请输入密码"
                  className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 pr-10 text-sm text-white"
                />
                <button
                  type="button"
                  onClick={() => setShowImportPassword(!showImportPassword)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                >
                  {showImportPassword ? (
                    <EyeSlashIcon className="h-4 w-4" />
                  ) : (
                    <EyeIcon className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Merge Mode */}
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-2">
                导入模式
              </label>
              <div className="flex gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="mergeMode"
                    value="replace"
                    checked={mergeMode === "replace"}
                    onChange={() => setMergeMode("replace")}
                    className="text-brand focus:ring-brand"
                  />
                  <span className="text-sm text-slate-300">替换现有配置</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="mergeMode"
                    value="merge"
                    checked={mergeMode === "merge"}
                    onChange={() => setMergeMode("merge")}
                    className="text-brand focus:ring-brand"
                  />
                  <span className="text-sm text-slate-300">合并（保留现有）</span>
                </label>
              </div>
            </div>

            <button
              onClick={handleImport}
              disabled={importing || !importData}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white font-medium transition-colors disabled:opacity-50"
            >
              {importing ? (
                <>
                  <ArrowPathIcon className="h-4 w-4 animate-spin" />
                  导入中...
                </>
              ) : (
                <>
                  <ArrowUpTrayIcon className="h-4 w-4" />
                  导入配置
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Info */}
      <div className="rounded-xl bg-slate-800/50 border border-white/5 p-5">
        <h4 className="font-semibold text-white mb-2">备份内容说明</h4>
        <ul className="text-sm text-slate-400 space-y-1">
          <li>
            <span className="text-slate-300">入口配置</span>：WireGuard 入口接口设置和客户端列表
          </li>
          <li>
            <span className="text-slate-300">自定义出口</span>：自定义 WireGuard 出口服务器配置
          </li>
          <li>
            <span className="text-slate-300">PIA 线路</span>：PIA VPN 地区选择配置
          </li>
          <li>
            <span className="text-slate-300">PIA 凭证</span>：PIA 账户用户名和密码
          </li>
          <li>
            <span className="text-slate-300">路由规则</span>：域名和 IP 分流规则
          </li>
          <li>
            <span className="text-slate-300">系统设置</span>：服务器公网地址等设置
          </li>
        </ul>
      </div>
    </div>
  );
}
