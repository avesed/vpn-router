import { useState, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../contexts/AuthContext";
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
  DocumentTextIcon,
  ExclamationTriangleIcon,
  LockClosedIcon
} from "@heroicons/react/24/outline";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export default function BackupRestore() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Export state
  const [exportPassword, setExportPassword] = useState("");
  const [showExportPassword, setShowExportPassword] = useState(false);
  const [exporting, setExporting] = useState(false);

  // Import state
  const [importPassword, setImportPassword] = useState("");
  const [showImportPassword, setShowImportPassword] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importData, setImportData] = useState("");
  const [checksumVerified, setChecksumVerified] = useState<boolean | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadStatus = async () => {
    try {
      setLoading(true);
      const data = await api.getBackupStatus();
      setStatus(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('backup.statusLoadFailed'));
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
    if (!exportPassword) {
      setError(t('backup.passwordRequired'));
      return;
    }

    setExporting(true);
    setError(null);
    try {
      const result = await api.exportBackup(exportPassword);

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

      setSuccessMessage(t('backup.exportedEncrypted'));
    } catch (err) {
      setError(err instanceof Error ? err.message : t('backup.exportFailed'));
    } finally {
      setExporting(false);
      setExportPassword("");
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const content = await file.text();
      setImportData(content);
      // Validate JSON
      const parsed = JSON.parse(content);

      // Check backup version
      if (parsed.version === "2.0") {
        setError(null);
      } else if (parsed.version === "1.0" || !parsed.version) {
        setError(null);
        // v1.0 backup - will be handled by backend
      } else {
        setError(t('backup.unsupportedVersion'));
        setImportData("");
      }
    } catch {
      setError(t('backup.invalidBackupFile'));
      setImportData("");
    }
  };

  const handleImport = async () => {
    if (!importData) {
      setError(t('backup.selectFileFirst'));
      return;
    }

    if (!importPassword) {
      setError(t('backup.passwordRequired'));
      return;
    }

    setImporting(true);
    setError(null);
    setChecksumVerified(null);
    try {
      const result = await api.importBackup(importData, importPassword);

      setChecksumVerified(result.checksum_verified ?? true);
      setImportData("");
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }

      // 备份导入后，数据库中的 JWT 秘钥可能已更改
      // 需要强制重新登录以获取新的有效 token
      logout();
      navigate("/login", {
        state: { message: t('backup.importSuccessRelogin') }
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : t('backup.importFailed'));
    } finally {
      setImporting(false);
      setImportPassword("");
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
    <div className="space-y-4 md:space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-white">{t('backup.title')}</h1>
          <p className="text-xs md:text-sm text-slate-400 mt-1">
            {t('backup.subtitle')}
          </p>
        </div>
        <button
          onClick={loadStatus}
          disabled={loading}
          className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
          title={t('common.refresh')}
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
      {checksumVerified !== null && (
        <div className={`rounded-xl p-4 flex items-center gap-2 ${
          checksumVerified
            ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
            : "bg-amber-500/10 border border-amber-500/20 text-amber-400"
        }`}>
          {checksumVerified ? (
            <>
              <ShieldCheckIcon className="h-5 w-5" />
              {t('backup.checksumVerified')}
            </>
          ) : (
            <>
              <ExclamationTriangleIcon className="h-5 w-5" />
              {t('backup.checksumNotVerified')}
            </>
          )}
        </div>
      )}

      {/* Current Status */}
      {status && (
        <div className="rounded-xl bg-white/5 border border-white/10 p-5">
          <h3 className="text-sm font-semibold text-slate-400 mb-3 flex items-center gap-2">
            <DocumentTextIcon className="h-4 w-4" />
            {t('backup.currentStatus')}
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="text-center p-3 rounded-lg bg-white/5">
              <p className="text-2xl font-bold text-white">
                {status.ingress_peer_count}
              </p>
              <p className="text-xs text-slate-400">{t('backup.ingressClients')}</p>
            </div>
            <div className="text-center p-3 rounded-lg bg-white/5">
              <p className="text-2xl font-bold text-white">
                {status.custom_egress_count}
              </p>
              <p className="text-xs text-slate-400">{t('backup.customEgress')}</p>
            </div>
            <div className="text-center p-3 rounded-lg bg-white/5">
              <p className="text-2xl font-bold text-white">
                {status.pia_profile_count}
              </p>
              <p className="text-xs text-slate-400">{t('backup.piaLines')}</p>
            </div>
            <div className="text-center p-3 rounded-lg bg-white/5">
              <div className="flex justify-center">
                {status.database_encrypted ? (
                  <LockClosedIcon className="h-6 w-6 text-emerald-400" />
                ) : (
                  <XCircleIcon className="h-6 w-6 text-amber-400" />
                )}
              </div>
              <p className="text-xs text-slate-400">{t('backup.databaseEncrypted')}</p>
            </div>
            <div className="text-center p-3 rounded-lg bg-white/5">
              <p className="text-lg font-bold text-white">
                {formatBytes(status.database_size_bytes || 0)}
              </p>
              <p className="text-xs text-slate-400">{t('backup.databaseSize')}</p>
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
              <h3 className="font-semibold text-white">{t('backup.export')}</h3>
              <p className="text-xs text-slate-400">{t('backup.exportDescV2')}</p>
            </div>
          </div>

          <div className="space-y-4">
            {/* Encryption Password (Required) */}
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t('backup.encryptionPassword')} <span className="text-red-400">*</span>
              </label>
              <div className="relative">
                <input
                  type={showExportPassword ? "text" : "password"}
                  value={exportPassword}
                  onChange={(e) => setExportPassword(e.target.value)}
                  placeholder={t('backup.encryptionPasswordHint')}
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
                {t('backup.encryptionNoteV2')}
              </p>
            </div>

            {/* Info about what's included */}
            <div className="rounded-lg bg-blue-500/10 border border-blue-500/20 p-3">
              <p className="text-xs text-blue-400">
                <ShieldCheckIcon className="h-4 w-4 inline mr-1" />
                {t('backup.exportInfoV2')}
              </p>
            </div>

            <button
              onClick={handleExport}
              disabled={exporting || !exportPassword}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-blue-500 hover:bg-blue-600 text-white font-medium transition-colors disabled:opacity-50"
            >
              {exporting ? (
                <>
                  <ArrowPathIcon className="h-4 w-4 animate-spin" />
                  {t('common.exporting')}
                </>
              ) : (
                <>
                  <ArrowDownTrayIcon className="h-4 w-4" />
                  {t('backup.exportBackup')}
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
              <h3 className="font-semibold text-white">{t('backup.import')}</h3>
              <p className="text-xs text-slate-400">{t('backup.importDescV2')}</p>
            </div>
          </div>

          <div className="space-y-4">
            {/* File Upload */}
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t('backup.selectBackupFile')}
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
                  {t('backup.backupLoaded')}
                </p>
              )}
            </div>

            {/* Decryption Password (Required) */}
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t('backup.decryptionPassword')} <span className="text-red-400">*</span>
              </label>
              <div className="relative">
                <input
                  type={showImportPassword ? "text" : "password"}
                  value={importPassword}
                  onChange={(e) => setImportPassword(e.target.value)}
                  placeholder={t('backup.decryptionPasswordHint')}
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

            {/* Warning about replacement */}
            <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-3">
              <p className="text-xs text-amber-400">
                <ExclamationTriangleIcon className="h-4 w-4 inline mr-1" />
                {t('backup.replaceWarning')}
              </p>
            </div>

            <button
              onClick={handleImport}
              disabled={importing || !importData || !importPassword}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white font-medium transition-colors disabled:opacity-50"
            >
              {importing ? (
                <>
                  <ArrowPathIcon className="h-4 w-4 animate-spin" />
                  {t('common.importing')}
                </>
              ) : (
                <>
                  <ArrowUpTrayIcon className="h-4 w-4" />
                  {t('backup.import')}
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Info */}
      <div className="rounded-xl bg-slate-800/50 border border-white/5 p-5">
        <h4 className="font-semibold text-white mb-2">{t('backup.backupContentsV2')}</h4>
        <ul className="text-sm text-slate-400 space-y-1">
          <li>
            <span className="text-slate-300">{t('backup.backupItems.database')}</span>：{t('backup.backupItems.databaseDesc')}
          </li>
          <li>
            <span className="text-slate-300">{t('backup.backupItems.encryptionKey')}</span>：{t('backup.backupItems.encryptionKeyDesc')}
          </li>
          <li>
            <span className="text-slate-300">{t('backup.backupItems.checksum')}</span>：{t('backup.backupItems.checksumDesc')}
          </li>
        </ul>
        <p className="text-xs text-slate-500 mt-3">
          {t('backup.v1CompatNote')}
        </p>
      </div>
    </div>
  );
}
