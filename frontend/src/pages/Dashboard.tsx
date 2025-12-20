import React, { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import StatsCard from "../components/StatsCard";
import { api } from "../api/client";
import type { GatewayStatus, DashboardStats } from "../types";
import {
  ServerIcon,
  ShieldCheckIcon,
  GlobeAltIcon,
  UsersIcon,
  BoltIcon,
  ShieldExclamationIcon
} from "@heroicons/react/24/outline";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip, LineChart, Line, XAxis, YAxis } from "recharts";

// 数据刷新间隔（毫秒）- 与后端 _HISTORY_INTERVAL 匹配
const REFRESH_INTERVAL = 1000;

// 时间范围配置
const TIME_RANGE_CONFIG = {
  "1m": { maxPoints: 60, intervalSec: 1, unit: "s", labelInterval: 10 },
  "1h": { maxPoints: 6, intervalSec: 600, unit: "m", labelInterval: 1 },
  "24h": { maxPoints: 24, intervalSec: 3600, unit: "h", labelInterval: 4 }
} as const;

// 出口流量饼图颜色
const CHART_COLORS = [
  "#3b82f6", // blue
  "#10b981", // emerald
  "#f59e0b", // amber
  "#ef4444", // red
  "#8b5cf6", // violet
  "#ec4899", // pink
  "#06b6d4", // cyan
  "#84cc16", // lime
  "#f97316", // orange
  "#6366f1", // indigo
];

// 格式化流量
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

// 保留字段名（不应作为出口名显示）
const RESERVED_KEYS = new Set(['index', '_ts', 'timestamp', 'name', 'value']);

export default function Dashboard() {
  const { t, i18n } = useTranslation();
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [dashboardStats, setDashboardStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // 时间范围选择
  const [timeRange, setTimeRange] = useState<"1m" | "1h" | "24h">("1m");

  // 本地维护的图表数据（实现平滑推进效果）
  const [localChartData, setLocalChartData] = useState<Record<string, number | string>[]>([]);
  const lastTimestampRef = useRef<number>(0);

  // 生成 X 轴刻度标签（基于固定位置，与数据数量无关）
  const formatXAxisTick = useCallback((index: number): string => {
    const config = TIME_RANGE_CONFIG[timeRange];
    const maxPoints = config.maxPoints;
    const pointsFromEnd = maxPoints - 1 - index;

    if (pointsFromEnd === 0) {
      return t('dashboard.now');
    }

    const timeValue = pointsFromEnd * config.intervalSec;
    if (timeRange === "1m") {
      return `-${timeValue}s`;
    } else if (timeRange === "1h") {
      return `-${timeValue / 60}m`;
    } else {
      return `-${timeValue / 3600}h`;
    }
  }, [timeRange, t]);

  // 转换数据点数组为图表格式（使用索引作为 X 轴键）
  const convertToChartData = useCallback((points: Array<{ timestamp: number; rates: Record<string, number> }>, range: "1m" | "1h" | "24h") => {
    const config = TIME_RANGE_CONFIG[range];
    const maxPoints = config.maxPoints;
    // 计算起始索引，使数据右对齐（最新数据在最右边）
    const startIndex = maxPoints - points.length;

    return points.map((point, i) => {
      const chartPoint: Record<string, number | string> = {
        index: startIndex + i,  // 固定位置索引
        _ts: point.timestamp
      };
      for (const [outbound, rate] of Object.entries(point.rates)) {
        chartPoint[outbound] = rate;
      }
      return chartPoint;
    });
  }, []);

  // 当 timeRange 变化时，重置图表数据
  useEffect(() => {
    setLocalChartData([]);
    lastTimestampRef.current = 0;
  }, [timeRange]);

  useEffect(() => {
    let mounted = true;
    const config = TIME_RANGE_CONFIG[timeRange];

    const fetchData = async () => {
      try {
        const [statusData, statsData] = await Promise.all([
          api.getStatus(),
          api.getDashboardStats(timeRange)
        ]);
        if (mounted) {
          setStatus(statusData);
          setDashboardStats(statsData);
          setError(null);

          // 更新图表数据
          if (statsData?.rate_history?.length) {
            if (timeRange === "1m") {
              // 1分钟模式：增量更新实现平滑推进效果
              const newPoints = statsData.rate_history.filter(
                (p: { timestamp: number }) => p.timestamp > lastTimestampRef.current
              );

              if (newPoints.length > 0) {
                lastTimestampRef.current = Math.max(...newPoints.map((p: { timestamp: number }) => p.timestamp));

                setLocalChartData(prev => {
                  const allPoints = [...prev.map(p => ({
                    timestamp: p._ts as number,
                    rates: Object.fromEntries(
                      Object.entries(p).filter(([k]) => k !== 'index' && k !== '_ts')
                    ) as Record<string, number>
                  })), ...newPoints];
                  const trimmed = allPoints.slice(-config.maxPoints);
                  return convertToChartData(trimmed, timeRange);
                });
              }
            } else {
              // 1小时/24小时模式：直接替换数据
              const latestTimestamp = Math.max(...statsData.rate_history.map((p: { timestamp: number }) => p.timestamp));
              if (latestTimestamp > lastTimestampRef.current) {
                lastTimestampRef.current = latestTimestamp;
                setLocalChartData(convertToChartData(statsData.rate_history, timeRange));
              }
            }
          }
        }
      } catch (err: any) {
        if (mounted) {
          setError(err.message);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, REFRESH_INTERVAL);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [timeRange, convertToChartData, t]);

  // 收集所有出口名称并排序（过滤保留字段）
  const outbounds = useMemo(() => {
    if (!localChartData.length) {
      return [];
    }
    const outboundSet = new Set<string>();
    localChartData.forEach(point => {
      Object.keys(point).forEach(key => {
        if (!RESERVED_KEYS.has(key)) {
          outboundSet.add(key);
        }
      });
    });
    return Array.from(outboundSet).sort((a, b) => {
      if (a === 'direct') return -1;
      if (b === 'direct') return 1;
      return a.localeCompare(b);
    });
  }, [localChartData]);

  // 用于显示的图表数据（只去掉 _ts，保留 index 供 XAxis 使用）
  const rateHistory = useMemo(() => {
    return localChartData.map(({ _ts, ...rest }) => rest);
  }, [localChartData]);

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
      description: status?.sing_box_running ? t('dashboard.serviceNormal') : t('dashboard.serviceStopped'),
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

  // 新增的实时统计卡片
  const liveStats: StatCard[] = [
    {
      title: t('dashboard.onlineClients'),
      value: dashboardStats ? `${dashboardStats.online_clients}/${dashboardStats.total_clients}` : "0/0",
      description: dashboardStats?.online_clients
        ? t('dashboard.clientsOnline', { online: dashboardStats.online_clients, total: dashboardStats.total_clients })
        : t('dashboard.totalClients'),
      icon: UsersIcon,
      status: dashboardStats?.online_clients ? "success" : "info"
    },
    {
      title: t('dashboard.activeConnections'),
      value: dashboardStats?.active_connections ?? 0,
      description: t('dashboard.connectionsActive'),
      icon: BoltIcon,
      status: dashboardStats?.active_connections ? "success" : "info"
    },
    {
      title: t('dashboard.adblockCount'),
      value: dashboardStats?.adblock_connections ?? 0,
      description: t('dashboard.adblockBlocked'),
      icon: ShieldExclamationIcon,
      status: dashboardStats?.adblock_connections ? "warning" : "info"
    }
  ];

  // 准备饼图数据（过滤保留字段）
  const trafficData = dashboardStats?.traffic_by_outbound
    ? Object.entries(dashboardStats.traffic_by_outbound)
        .filter(([name]) => !RESERVED_KEYS.has(name))
        .map(([name, { download, upload }]) => ({
          name,
          value: download + upload,
          download,
          upload
        }))
        .filter(item => item.value > 0)
        .sort((a, b) => b.value - a.value)
    : [];

  // 自定义 Tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="rounded-lg bg-slate-800 px-3 py-2 shadow-lg border border-slate-700">
          <p className="text-sm font-medium text-white">{data.name}</p>
          <p className="text-xs text-slate-300">
            {t('dashboard.download')}: {formatBytes(data.download)}
          </p>
          <p className="text-xs text-slate-300">
            {t('dashboard.upload')}: {formatBytes(data.upload)}
          </p>
          <p className="text-xs text-slate-400 mt-1">
            {t('dashboard.total')}: {formatBytes(data.value)}
          </p>
        </div>
      );
    }
    return null;
  };

  // 自定义 Legend - 显示所有出口（包括无流量的）
  const renderLegend = () => {
    return (
      <div className="flex flex-wrap justify-center gap-3 mt-4">
        {outbounds.map((name, index) => (
          <div key={`legend-${index}`} className="flex items-center gap-1.5">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: CHART_COLORS[index % CHART_COLORS.length] }}
            />
            <span className="text-xs text-slate-300">{name}</span>
          </div>
        ))}
      </div>
    );
  };

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
          {/* 主要状态卡片 */}
          <div className="grid gap-5 md:grid-cols-3">
            {mainStats.map((card) => (
              <StatsCard key={card.title} {...card} />
            ))}
          </div>

          {/* 实时统计卡片 */}
          <div className="grid gap-5 md:grid-cols-3">
            {liveStats.map((card) => (
              <StatsCard key={card.title} {...card} />
            ))}
          </div>

          {/* 图表区域 */}
          <div className="grid gap-5 lg:grid-cols-2">
            {/* 出口流量分布饼图 */}
            <section className="rounded-3xl border border-white/5 bg-slate-900/40 p-6 shadow-inner shadow-black/40">
              <div className="mb-4">
                <h3 className="text-lg font-semibold text-white">{t('dashboard.trafficDistribution')}</h3>
                <p className="mt-1 text-sm text-slate-400">{t('dashboard.trafficDistributionDesc')}</p>
              </div>

              {trafficData.length > 0 ? (
                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={trafficData}
                        cx="50%"
                        cy="50%"
                        innerRadius={45}
                        outerRadius={75}
                        paddingAngle={2}
                        dataKey="value"
                        nameKey="name"
                      >
                        {trafficData.map((item) => {
                          // 使用 outbounds 数组中的索引来确定颜色，保持与图例一致
                          const colorIndex = outbounds.indexOf(item.name);
                          const color = colorIndex >= 0
                            ? CHART_COLORS[colorIndex % CHART_COLORS.length]
                            : CHART_COLORS[0];
                          return (
                            <Cell
                              key={`cell-${item.name}`}
                              fill={color}
                              stroke="transparent"
                            />
                          );
                        })}
                      </Pie>
                      <Tooltip content={<CustomTooltip />} />
                      <Legend content={renderLegend} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="flex items-center justify-center h-56 text-slate-500">
                  {t('dashboard.noTrafficData')}
                </div>
              )}
            </section>

            {/* 实时网速图表 */}
            <section className="rounded-3xl border border-white/5 bg-slate-900/40 p-6 shadow-inner shadow-black/40">
              <div className="mb-4 flex items-start justify-between">
                <div>
                  <h3 className="text-lg font-semibold text-white">{t('dashboard.networkSpeed')}</h3>
                  <p className="mt-1 text-sm text-slate-400">{t('dashboard.networkSpeedDesc')}</p>
                </div>
                <div className="flex gap-1">
                  {(["1m", "1h", "24h"] as const).map((range) => (
                    <button
                      key={range}
                      onClick={() => setTimeRange(range)}
                      className={`px-2 py-1 text-xs rounded transition-colors ${
                        timeRange === range
                          ? "bg-blue-500 text-white"
                          : "bg-slate-700/50 text-slate-400 hover:bg-slate-600/50"
                      }`}
                    >
                      {t(`dashboard.timeRange${range.toUpperCase()}`)}
                    </button>
                  ))}
                </div>
              </div>

              {rateHistory.length > 1 ? (
                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={rateHistory}>
                      <XAxis
                        dataKey="index"
                        type="number"
                        domain={[0, TIME_RANGE_CONFIG[timeRange].maxPoints - 1]}
                        stroke="#64748b"
                        fontSize={10}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={formatXAxisTick}
                        interval="preserveStartEnd"
                      />
                      <YAxis
                        stroke="#64748b"
                        fontSize={10}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={(value) => `${value.toFixed(0)}`}
                        width={35}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1e293b',
                          border: '1px solid #334155',
                          borderRadius: '8px',
                          fontSize: '12px'
                        }}
                        labelStyle={{ color: '#e2e8f0' }}
                        formatter={(value: number) => [`${value.toFixed(1)} KB/s`, '']}
                      />
                      <Legend content={renderLegend} />
                      {outbounds.map((outbound, index) => (
                        <Line
                          key={outbound}
                          type="monotone"
                          dataKey={outbound}
                          stroke={CHART_COLORS[index % CHART_COLORS.length]}
                          strokeWidth={2}
                          dot={false}
                          name={outbound}
                          isAnimationActive={false}
                        />
                      ))}
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="flex items-center justify-center h-56 text-slate-500">
                  {t('dashboard.collectingData')}
                </div>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}
