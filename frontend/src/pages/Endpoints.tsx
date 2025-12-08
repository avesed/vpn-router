import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import EndpointCard from "../components/EndpointCard";
import { api } from "../api/client";
import type { Endpoint } from "../types";
import { ArrowPathIcon } from "@heroicons/react/24/outline";

export default function Endpoints() {
  const { t } = useTranslation();
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingTag, setSavingTag] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchEndpoints = async () => {
    setLoading(true);
    try {
      const data = await api.getEndpoints();
      // Filter out wg-server (managed in Ingress Manager)
      const exitEndpoints = data.endpoints.filter(ep => ep.tag !== "wg-server");
      setEndpoints(exitEndpoints);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEndpoints();
  }, []);

  const handleUpdate = async (tag: string, payload: Partial<Endpoint>) => {
    setSavingTag(tag);
    try {
      await api.updateEndpoint(tag, payload);
      setEndpoints((prev) => prev.map((ep) => (ep.tag === tag ? { ...ep, ...payload } : ep)));
    } catch (error) {
      console.error("Failed to update endpoint:", error);
    } finally {
      setSavingTag(null);
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">{t('endpoints.title')}</h2>
          <p className="mt-1 text-sm text-slate-400">
            {t('endpoints.subtitle')}
          </p>
        </div>
        <button
          onClick={fetchEndpoints}
          disabled={loading}
          className="flex items-center gap-2 rounded-xl bg-white/5 px-4 py-2 text-sm text-slate-300 transition hover:bg-white/10 disabled:opacity-50"
        >
          <ArrowPathIcon className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          {t('common.refresh')}
        </button>
      </div>

      {error && (
        <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-5 py-4">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 rounded-lg bg-rose-500/20 p-2">
              <svg className="h-5 w-5 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div className="flex-1">
              <p className="font-semibold text-rose-200">{t('common.loadFailed')}</p>
              <p className="mt-1 text-sm text-rose-300">{error}</p>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="flex flex-col items-center gap-4">
            <div className="h-12 w-12 animate-spin rounded-full border-4 border-slate-700 border-t-blue-500" />
            <p className="text-slate-400">{t('endpoints.loadingEndpoints')}</p>
          </div>
        </div>
      ) : endpoints.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-white/5 bg-slate-900/40 py-16">
          <div className="rounded-full bg-slate-800 p-4 mb-4">
            <svg className="h-12 w-12 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
          </div>
          <p className="text-lg font-semibold text-slate-300">{t('endpoints.noEndpoints')}</p>
          <p className="mt-1 text-sm text-slate-500">{t('endpoints.checkConfig')}</p>
        </div>
      ) : (
        <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-2">
          {endpoints.map((endpoint) => (
            <EndpointCard
              key={endpoint.tag}
              endpoint={endpoint}
              isSaving={savingTag === endpoint.tag}
              onUpdate={(payload) => handleUpdate(endpoint.tag, payload)}
            />
          ))}
        </div>
      )}

      {!loading && endpoints.length > 0 && (
        <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-4">
          <p className="text-xs text-blue-300">
            {t('endpoints.restartNote')}
          </p>
        </div>
      )}
    </div>
  );
}
