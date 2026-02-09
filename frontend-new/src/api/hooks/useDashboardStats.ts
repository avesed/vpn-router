import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import type { DashboardStats } from "../../types";

export function useDashboardStats(timeRange: "1m" | "1h" | "24h" = "1m") {
  return useQuery<DashboardStats>({
    queryKey: ["dashboard-stats", timeRange],
    queryFn: () => api.getDashboardStats(timeRange),
    refetchInterval: 2000, // Real-time updates every 2 seconds
  });
}
