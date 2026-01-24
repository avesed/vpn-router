import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { toast } from "sonner";
import type { ShadowsocksInboundConfigUpdateRequest } from "../../types";

export function useShadowsocksIngressConfig() {
  return useQuery({
    queryKey: ["shadowsocks-ingress", "config"],
    queryFn: () => api.getShadowsocksInboundConfig(),
  });
}

export function useUpdateShadowsocksIngressConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: ShadowsocksInboundConfigUpdateRequest) =>
      api.updateShadowsocksInboundConfig(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shadowsocks-ingress", "config"] });
      queryClient.invalidateQueries({ queryKey: ["shadowsocks-ingress", "status"] });
      toast.success("Shadowsocks ingress configuration updated");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update Shadowsocks ingress: ${error.message}`);
    },
  });
}

export function useShadowsocksIngressStatus() {
  return useQuery({
    queryKey: ["shadowsocks-ingress", "status"],
    queryFn: () => api.getShadowsocksInboundStatus(),
    refetchInterval: 5000, // Update every 5 seconds
  });
}

export function useStopShadowsocksIngress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.stopShadowsocksIngress(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shadowsocks-ingress", "config"] });
      queryClient.invalidateQueries({ queryKey: ["shadowsocks-ingress", "status"] });
      toast.success("Shadowsocks ingress stopped");
    },
    onError: (error: Error) => {
      toast.error(`Failed to stop Shadowsocks ingress: ${error.message}`);
    },
  });
}

export function useShadowsocksIngressOutbound() {
  return useQuery({
    queryKey: ["ingress", "shadowsocks", "outbound"],
    queryFn: () => api.getShadowsocksIngressOutbound(),
  });
}

export function useSetShadowsocksIngressOutbound() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (outbound: string | null) => api.setShadowsocksIngressOutbound(outbound),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ingress", "shadowsocks", "outbound"] });
      toast.success("Shadowsocks ingress outbound updated");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update Shadowsocks ingress outbound: ${error.message}`);
    },
  });
}
