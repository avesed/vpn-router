import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type { NodeChainUpdateRequest } from "../../types";

// Keys
export const chainKeys = {
  all: ["chains"] as const,
  detail: (tag: string) => ["chains", tag] as const,
  stats: ["chains", "stats"] as const,
};

// Hooks
export function useNodeChains() {
  return useQuery({
    queryKey: chainKeys.all,
    queryFn: api.getNodeChains,
  });
}

export function useNodeChain(tag: string) {
  return useQuery({
    queryKey: chainKeys.detail(tag),
    queryFn: () => api.getNodeChain(tag),
    enabled: !!tag,
  });
}

export function useCreateNodeChain() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.createNodeChain,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: chainKeys.all });
    },
  });
}

export function useUpdateNodeChain() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tag, data }: { tag: string; data: NodeChainUpdateRequest }) =>
      api.updateNodeChain(tag, data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: chainKeys.all });
      queryClient.invalidateQueries({ queryKey: chainKeys.detail(data.chain.tag) });
    },
  });
}

export function useDeleteNodeChain() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deleteNodeChain,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: chainKeys.all });
    },
  });
}

export function useActivateChain() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.activateChain,
    onSuccess: (_data, tag) => {
      queryClient.invalidateQueries({ queryKey: chainKeys.all });
      queryClient.invalidateQueries({ queryKey: chainKeys.detail(tag) });
    },
  });
}

export function useDeactivateChain() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deactivateChain,
    onSuccess: (_data, tag) => {
      queryClient.invalidateQueries({ queryKey: chainKeys.all });
      queryClient.invalidateQueries({ queryKey: chainKeys.detail(tag) });
    },
  });
}

export function useChainHealthCheck() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.triggerChainHealthCheck,
    onSuccess: (_data, tag) => {
      queryClient.invalidateQueries({ queryKey: chainKeys.all });
      queryClient.invalidateQueries({ queryKey: chainKeys.detail(tag) });
      queryClient.invalidateQueries({ queryKey: chainKeys.stats });
    },
  });
}

export function useChainStats() {
  return useQuery({
    queryKey: chainKeys.stats,
    queryFn: api.getChainStats,
    refetchInterval: 5000,
  });
}
