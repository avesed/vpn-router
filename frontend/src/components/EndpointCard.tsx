import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Endpoint, WireGuardPeer } from "../types";
import {
  ChevronDownIcon,
  ChevronUpIcon,
  CheckCircleIcon,
  ExclamationCircleIcon
} from "@heroicons/react/24/outline";

interface Props {
  endpoint: Endpoint;
  isSaving: boolean;
  onUpdate: (payload: Partial<Endpoint>) => Promise<void>;
}

export default function EndpointCard({ endpoint, isSaving, onUpdate }: Props) {
  const { t } = useTranslation();
  const [form, setForm] = useState({
    address: endpoint.address?.[0] ?? "",
    privateKey: endpoint.private_key ?? "",
    peerAddress: endpoint.peers?.[0]?.address ?? "",
    peerPort: endpoint.peers?.[0]?.port?.toString() ?? "",
    peerKey: endpoint.peers?.[0]?.public_key ?? ""
  });
  const [status, setStatus] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const handleChange = (field: keyof typeof form, value: string) => {
    setForm((prev) => ({ ...prev, [field]: value }));
    setStatus(null);
  };

  const handleSubmit = async () => {
    const peer: WireGuardPeer = {
      address: form.peerAddress,
      port: Number(form.peerPort) || 0,
      public_key: form.peerKey,
      allowed_ips: endpoint.peers?.[0]?.allowed_ips ?? ["0.0.0.0/0", "::/0"]
    };
    setStatus(null);
    setIsSuccess(false);
    try {
      await onUpdate({
        address: form.address ? [form.address] : endpoint.address,
        private_key: form.privateKey,
        peers: [peer]
      });
      setStatus(t("common.success"));
      setIsSuccess(true);
      setTimeout(() => {
        setStatus(null);
        setIsSuccess(false);
      }, 3000);
    } catch (error: unknown) {
      // M7 修复: 使用 unknown 类型
      const message = error instanceof Error ? error.message : t("common.saveFailed");
      setStatus(message);
      setIsSuccess(false);
    }
  };

  const isConfigured = form.peerAddress && form.peerPort && form.peerKey;

  return (
    <div className="group rounded-2xl border border-white/5 bg-gradient-to-br from-slate-800/60 to-slate-800/40 p-6 shadow-lg shadow-black/20 transition-all hover:shadow-xl hover:shadow-black/30 hover:border-white/10">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <div className={`h-3 w-3 rounded-full ${isConfigured ? 'bg-emerald-400 shadow-lg shadow-emerald-400/50' : 'bg-slate-500'}`} />
            <div>
              <p className="text-xs uppercase tracking-widest text-slate-400">{t("endpoint.endpoint")}</p>
              <h3 className="text-xl font-bold text-white">{endpoint.tag}</h3>
            </div>
          </div>

          {/* Quick Info */}
          <div className="mt-3 flex flex-wrap gap-2">
            <span className="rounded-lg bg-brand/10 px-2.5 py-1 text-xs font-medium text-brand border border-brand/20">
              {endpoint.type.toUpperCase()}
            </span>
            {form.peerAddress && (
              <span className="rounded-lg bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-300 border border-emerald-500/20">
                {form.peerAddress}:{form.peerPort}
              </span>
            )}
          </div>
        </div>

        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="rounded-xl bg-white/5 p-2 transition hover:bg-white/10"
        >
          {isExpanded ? (
            <ChevronUpIcon className="h-5 w-5 text-slate-400" />
          ) : (
            <ChevronDownIcon className="h-5 w-5 text-slate-400" />
          )}
        </button>
      </div>

      {/* Expanded Form */}
      {isExpanded && (
        <div className="mt-5 space-y-4 border-t border-white/5 pt-5">
          <div>
            <label className="text-xs font-semibold uppercase tracking-widest text-slate-400">
              {t("endpoint.localAddress")}
            </label>
            <input
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/60 px-4 py-2.5 text-sm text-white placeholder-slate-500 transition focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
              value={form.address}
              onChange={(e) => handleChange("address", e.target.value)}
              placeholder="172.31.x.x/32"
            />
          </div>

          <div>
            <label className="text-xs font-semibold uppercase tracking-widest text-slate-400">
              {t("endpoint.privateKey")}
            </label>
            <input
              type="password"
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/60 px-4 py-2.5 text-sm font-mono text-white placeholder-slate-500 transition focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
              value={form.privateKey}
              onChange={(e) => handleChange("privateKey", e.target.value)}
              placeholder="••••••••••••••••••••••••"
            />
          </div>

          <div className="rounded-xl bg-white/5 p-4">
            <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-slate-400">
              {t("endpoint.peerConfig")}
            </p>

            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium text-slate-400">{t("common.address")}</label>
                  <input
                    className="mt-1.5 w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white placeholder-slate-500 transition focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
                    value={form.peerAddress}
                    onChange={(e) => handleChange("peerAddress", e.target.value)}
                    placeholder="10.x.x.x"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-400">{t("common.port")}</label>
                  <input
                    type="number"
                    className="mt-1.5 w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white placeholder-slate-500 transition focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
                    value={form.peerPort}
                    onChange={(e) => handleChange("peerPort", e.target.value)}
                    placeholder="51820"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-medium text-slate-400">{t("endpoint.publicKey")}</label>
                <input
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm font-mono text-white placeholder-slate-500 transition focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
                  value={form.peerKey}
                  onChange={(e) => handleChange("peerKey", e.target.value)}
                  placeholder="Base64 encoded public key"
                />
              </div>
            </div>
          </div>

          {status && (
            <div className={`flex items-center gap-2 rounded-xl px-4 py-3 ${
              isSuccess
                ? 'bg-emerald-500/10 border border-emerald-500/20'
                : 'bg-rose-500/10 border border-rose-500/20'
            }`}>
              {isSuccess ? (
                <CheckCircleIcon className="h-5 w-5 text-emerald-400" />
              ) : (
                <ExclamationCircleIcon className="h-5 w-5 text-rose-400" />
              )}
              <p className={`text-sm font-medium ${isSuccess ? 'text-emerald-300' : 'text-rose-300'}`}>
                {status}
              </p>
            </div>
          )}

          <button
            onClick={handleSubmit}
            disabled={isSaving}
            className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-brand to-blue-600 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-brand/20 transition hover:shadow-xl hover:shadow-brand/30 disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
          >
            {isSaving ? (
              <>
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                {t("common.saving")}
              </>
            ) : (
              t("endpoint.saveChanges")
            )}
          </button>
        </div>
      )}
    </div>
  );
}
