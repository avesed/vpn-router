import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type { 
  DirectEgressUpdateRequest,
  WarpEgressUpdateRequest,
  WarpEgressEndpointRequest,
  WarpEgressLicenseRequest,
  WarpEndpointTestRequest
} from "../../types";

// Keys
export const egressKeys = {
  all: ["egress"] as const,
  custom: ["egress", "custom"] as const,
  direct: ["egress", "direct"] as const,
  warp: ["egress", "warp"] as const,
  openvpn: ["egress", "openvpn"] as const,
  v2ray: ["egress", "v2ray"] as const,
  pia: ["egress", "pia"] as const,
};

// All Egress
export function useAllEgress() {
  return useQuery({
    queryKey: egressKeys.all,
    queryFn: api.getAllEgress,
  });
}

// Egress Traffic Stats (for WireGuard tunnels)
export function useEgressTraffic() {
  return useQuery({
    queryKey: ["egress", "traffic"] as const,
    queryFn: api.getEgressTraffic,
    refetchInterval: 10000, // Refresh every 10 seconds
  });
}

// Test Egress
export function useTestEgress() {
  return useMutation({
    mutationFn: ({ tag, timeout }: { tag: string; timeout?: number }) => 
      api.testEgress(tag, timeout),
  });
}

// Custom (WireGuard) Egress
export function useCreateCustomEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.createCustomEgress,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.custom });
    },
  });
}

export function useDeleteCustomEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deleteCustomEgress,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.custom });
    },
  });
}

export function useParseWireGuardConf() {
  return useMutation({
    mutationFn: api.parseWireGuardConf,
  });
}

// Direct Egress
export function useDirectEgress() {
  return useQuery({
    queryKey: egressKeys.direct,
    queryFn: api.getDirectEgress,
  });
}

export function useCreateDirectEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.createDirectEgress,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.direct });
    },
  });
}

export function useUpdateDirectEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tag, data }: { tag: string; data: DirectEgressUpdateRequest }) =>
      api.updateDirectEgress(tag, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.direct });
    },
  });
}

export function useDeleteDirectEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deleteDirectEgress,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.direct });
    },
  });
}

// WARP Egress
export function useWarpEgress() {
  return useQuery({
    queryKey: egressKeys.warp,
    queryFn: api.getWarpEgress,
  });
}

export function useRegisterWarpEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.registerWarpEgress,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.warp });
    },
  });
}

export function useUpdateWarpEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tag, data }: { tag: string; data: WarpEgressUpdateRequest }) =>
      api.updateWarpEgress(tag, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.warp });
    },
  });
}

export function useDeleteWarpEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deleteWarpEgress,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.warp });
    },
  });
}

export function useReregisterWarpEgress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.reregisterWarpEgress,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.warp });
    },
  });
}

export function useApplyWarpLicense() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tag, data }: { tag: string; data: WarpEgressLicenseRequest }) =>
      api.applyWarpLicense(tag, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.warp });
    },
  });
}

export function useSetWarpEndpoint() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tag, data }: { tag: string; data: WarpEgressEndpointRequest }) =>
      api.setWarpEndpoint(tag, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.warp });
    },
  });
}

export function useTestWarpEndpoints() {
  return useMutation({
    mutationFn: (data: WarpEndpointTestRequest) => api.testWarpEndpoints(data),
  });
}

// PIA Egress
export function useRefreshPiaCredentials() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (profileTag: string) => api.reconnectProfile(profileTag),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: egressKeys.pia });
    },
  });
}
