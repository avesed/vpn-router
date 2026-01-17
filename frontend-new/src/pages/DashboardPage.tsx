import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { useStatus } from "@/api/hooks/useStatus";
import { useDashboardStats } from "@/api/hooks/useDashboardStats";
import { 
  Activity, 
  Shield, 
  Users, 
  Zap, 
} from "lucide-react";
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from "recharts";
import { formatBytes } from "@/lib/utils";

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#82ca9d'];

type TimeRange = "1m" | "1h" | "24h";

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  
  if (days > 0) {
    return `${days}d ${hours}h`;
  } else if (hours > 0) {
    return `${hours}h ${minutes}m`;
  } else {
    return `${minutes}m`;
  }
}

export function DashboardPage() {
  const { t } = useTranslation();
  const [timeRange, setTimeRange] = useState<TimeRange>("1m");
  const { data: status } = useStatus();
  const { data: stats, isLoading: isStatsLoading, error: statsError } = useDashboardStats(timeRange);

  const pieData = stats?.traffic_by_outbound
    ? Object.entries(stats.traffic_by_outbound).map(([name, data]) => ({
        name,
        value: data.download + data.upload
      }))
    : [];

  const areaData = stats?.rate_history?.map(point => ({
    time: new Date(point.timestamp * 1000).toLocaleTimeString(),
    ...point.rates
  })) || [];

  // Get all unique keys from rate history for the area chart
  const rateKeys = stats?.rate_history?.[0]?.rates
    ? Object.keys(stats.rate_history[0].rates)
    : [];

  // Check if we have any data to display
  const hasTrafficData = pieData.length > 0;
  const hasRateData = areaData.length > 0 && rateKeys.length > 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          {t("dashboard.title")}
        </h1>
        <p className="text-muted-foreground">{t("dashboard.subtitle")}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t("dashboard.onlineClients")}
            </CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.online_clients ?? "-"} / {stats?.total_clients ?? "-"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t("dashboard.activeConnections")}
            </CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.active_connections ?? "-"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t("dashboard.adblockCount")}
            </CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.adblock_connections ?? "-"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t("dashboard.routerStatus")}
            </CardTitle>
            <Zap className={`h-4 w-4 ${status?.rust_router_running ? "text-green-500" : "text-red-500"}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {status?.rust_router_running ? t("common.running") : t("common.stopped")}
            </div>
            {status?.rust_router?.uptime_secs !== undefined && status.rust_router.uptime_secs > 0 && (
              <p className="text-xs text-muted-foreground">
                {t("dashboard.uptime")}: {formatUptime(status.rust_router.uptime_secs)}
              </p>
            )}
            {status?.timestamp && (
              <p className="text-xs text-muted-foreground">
                {t("dashboard.lastUpdate")}: {new Date(status.timestamp).toLocaleTimeString()}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>{t("dashboard.networkSpeed")}</CardTitle>
            <ToggleGroup
              type="single"
              value={timeRange}
              onValueChange={(value: string) => value && setTimeRange(value as TimeRange)}
              className="h-8"
            >
              <ToggleGroupItem value="1m" aria-label="1 minute" className="text-xs px-2 h-7">
                {t("dashboard.1m", { defaultValue: "1m" })}
              </ToggleGroupItem>
              <ToggleGroupItem value="1h" aria-label="1 hour" className="text-xs px-2 h-7">
                {t("dashboard.1h", { defaultValue: "1h" })}
              </ToggleGroupItem>
              <ToggleGroupItem value="24h" aria-label="24 hours" className="text-xs px-2 h-7">
                {t("dashboard.24h", { defaultValue: "24h" })}
              </ToggleGroupItem>
            </ToggleGroup>
          </CardHeader>
          <CardContent className="pl-2">
            <div className="h-[300px]">
              {isStatsLoading ? (
                <div className="flex items-center justify-center h-full">
                  <p className="text-muted-foreground">{t("common.loading")}</p>
                </div>
              ) : statsError ? (
                <div className="flex items-center justify-center h-full">
                  <p className="text-destructive">{t("common.error")}: {(statsError as Error).message}</p>
                </div>
              ) : !hasRateData ? (
                <div className="flex items-center justify-center h-full">
                  <p className="text-muted-foreground">{t("dashboard.collectingData")}</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={areaData}>
                    <defs>
                      {rateKeys.map((key, index) => (
                        <linearGradient key={key} id={`color${key}`} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={COLORS[index % COLORS.length]} stopOpacity={0.8}/>
                          <stop offset="95%" stopColor={COLORS[index % COLORS.length]} stopOpacity={0}/>
                        </linearGradient>
                      ))}
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                    <XAxis
                      dataKey="time"
                      stroke="#888888"
                      fontSize={12}
                      tickLine={false}
                      axisLine={false}
                    />
                    <YAxis
                      stroke="#888888"
                      fontSize={12}
                      tickLine={false}
                      axisLine={false}
                      tickFormatter={(value) => formatBytes(value * 1024) + '/s'}
                    />
                    <Tooltip
                      contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                      itemStyle={{ color: 'hsl(var(--foreground))' }}
                      formatter={(value: number | undefined) => [formatBytes((value || 0) * 1024) + '/s', t("dashboard.rate")] as [string, string]}
                    />
                    {rateKeys.map((key, index) => (
                      <Area
                        key={key}
                        type="monotone"
                        dataKey={key}
                        stroke={COLORS[index % COLORS.length]}
                        fillOpacity={1}
                        fill={`url(#color${key})`}
                        stackId="1"
                        isAnimationActive={false}
                      />
                    ))}
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>{t("dashboard.trafficDistribution")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {isStatsLoading ? (
                <div className="flex items-center justify-center h-full">
                  <p className="text-muted-foreground">{t("common.loading")}</p>
                </div>
              ) : statsError ? (
                <div className="flex items-center justify-center h-full">
                  <p className="text-destructive">{t("common.error")}: {(statsError as Error).message}</p>
                </div>
              ) : !hasTrafficData ? (
                <div className="flex items-center justify-center h-full">
                  <p className="text-muted-foreground">{t("dashboard.noTrafficData")}</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {pieData.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value: number | undefined) => [formatBytes(value || 0), t("dashboard.traffic")] as [string, string]}
                      contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                      itemStyle={{ color: 'hsl(var(--foreground))' }}
                    />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
