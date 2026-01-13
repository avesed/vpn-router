import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import type { GatewayStatus } from "../../types";

export function useStatus() {
  return useQuery<GatewayStatus>({
    queryKey: ["status"],
    queryFn: api.getStatus,
    refetchInterval: 5000, // Refresh every 5 seconds
  });
}
