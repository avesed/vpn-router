import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import StatsCard from "../components/StatsCard";
import { api } from "../api/client";
import type { GatewayStatus } from "../types";
import {
  ServerIcon,
  ShieldCheckIcon,
  ClockIcon,
  SignalIcon,
  GlobeAltIcon,
  CpuChipIcon
} from "@heroicons/react/24/outline";

export default function Dashboard() {
  const { t, i18n } = useTranslation();
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  useEffect(() => {
    let mounted = true;
    const fetchStatus = async () => {
      try {
        const data = await api.getStatus();
        if (mounted) {
          setStatus(data);
          setError(null);
          setLastUpdate(new Date());
        }
      } catch (err: any) {
        if (mounted) {
          setError(err.message);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const formatUptime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    if (hours > 0) return `${hours}${t('dashboard.hours')}${minutes % 60}${t('dashboard.minutes')}`;
    return `${minutes}${t('dashboard.minutes')}`;
  };

  const locale = i18n.language === 'zh' ? 'zh-CN' : 'en-US';

  type StatusType = "success" | "warning" | "error" | "info";
  interface StatCard {
    title: string;
    value: React.ReactNode;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
    status: StatusType;
  }

  const mainStats: StatCard[] = [
    {
      title: t('dashboard.singboxStatus'),
      value: status?.sing_box_running ? t('common.running') : t('common.stopped'),
      description: status ? `${t('dashboard.runningTime')}: ${formatUptime(status.timestamp)}` : "",
      icon: ServerIcon,
      status: status?.sing_box_running ? "success" : "error"
    },
    {
      title: t('dashboard.piaLines'),
      value: status?.pia_profiles?.length ?? 0,
      description: status?.pia_profiles?.length ? t('dashboard.linesConfigured') : t('dashboard.notConfigured'),
      icon: GlobeAltIcon,
      status: status?.pia_profiles?.length ? "success" : "warning"
    },
    {
      title: t('dashboard.configStatus'),
      value: status?.config_mtime ? t('common.synced') : t('common.unknown'),
      description: status?.config_mtime ? new Date(status.config_mtime * 1000).toLocaleString(locale, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      }) : "--",
      icon: ShieldCheckIcon,
      status: "info"
    }
  ];

  const additionalStats: StatCard[] = [
    {
      title: t('dashboard.lastUpdate'),
      value: lastUpdate.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      description: t('dashboard.autoRefresh'),
      icon: ClockIcon,
      status: "info"
    },
    {
      title: t('dashboard.gatewayType'),
      value: "WireGuard",
      description: t('dashboard.basedOnSingbox'),
      icon: CpuChipIcon,
      status: "info"
    },
    {
      title: t('dashboard.connectionStatus'),
      value: status?.sing_box_running ? t('common.online') : t('common.offline'),
      description: error ? t('dashboard.connectionError') : t('dashboard.normal'),
      icon: SignalIcon,
      status: error ? "error" : "success"
    }
  ];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">{t('dashboard.title')}</h2>
          <p className="mt-1 text-sm text-slate-400">{t('dashboard.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2 rounded-full bg-white/5 px-4 py-2">
          <div className={`h-2 w-2 rounded-full ${status?.sing_box_running ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
          <span className="text-sm text-slate-300">{status?.sing_box_running ? t('dashboard.serviceRunning') : t('dashboard.serviceStopped')}</span>
        </div>
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
              <p className="font-semibold text-rose-200">{t('dashboard.connectionError')}</p>
              <p className="mt-1 text-sm text-rose-300">{error}</p>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="flex flex-col items-center gap-4">
            <div className="h-12 w-12 animate-spin rounded-full border-4 border-slate-700 border-t-blue-500" />
            <p className="text-slate-400">{t('common.loading')}</p>
          </div>
        </div>
      ) : (
        <>
          <div className="grid gap-5 md:grid-cols-3">
            {mainStats.map((card) => (
              <StatsCard key={card.title} {...card} />
            ))}
          </div>

          <div className="grid gap-5 md:grid-cols-3">
            {additionalStats.map((card) => (
              <StatsCard key={card.title} {...card} />
            ))}
          </div>
        </>
      )}

      <section className="rounded-3xl border border-white/5 bg-slate-900/40 p-6 shadow-inner shadow-black/40">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white">{t('dashboard.wireguardInterface')}</h3>
            <p className="mt-1 text-sm text-slate-400">{t('dashboard.wireguardInterfaceDesc')}</p>
          </div>
          <button
            onClick={() => window.location.reload()}
            className="rounded-xl bg-white/5 px-4 py-2 text-sm text-slate-300 transition hover:bg-white/10"
          >
            {t('common.refresh')}
          </button>
        </div>
        <div className="rounded-2xl bg-black/30 p-4">
          <pre className="max-h-96 overflow-auto text-xs text-emerald-200 font-mono">
            {typeof status?.wireguard_interface?.raw === "string" ? status.wireguard_interface.raw : t('dashboard.noWireguardStatus')}
          </pre>
        </div>
      </section>
    </div>
  );
}
