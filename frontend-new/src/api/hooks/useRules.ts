import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type { RouteRule } from "../../types";

// Keys
export const ruleKeys = {
  all: ["rules"] as const,
  defaultOutbound: ["rules", "defaultOutbound"] as const,
};

// Hooks
export function useRouteRules() {
  return useQuery({
    queryKey: ruleKeys.all,
    queryFn: api.getRouteRules,
  });
}

export function useUpdateRouteRules() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ rules, defaultOutbound }: { rules: RouteRule[]; defaultOutbound: string }) =>
      api.updateRouteRules(rules, defaultOutbound),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ruleKeys.all });
      queryClient.invalidateQueries({ queryKey: ruleKeys.defaultOutbound });
    },
  });
}

export function useDefaultOutbound() {
  return useQuery({
    queryKey: ruleKeys.defaultOutbound,
    queryFn: api.getDefaultOutbound,
  });
}

export function useSwitchDefaultOutbound() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.switchDefaultOutbound,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ruleKeys.defaultOutbound });
      queryClient.invalidateQueries({ queryKey: ruleKeys.all });
    },
  });
}

export function useAddCustomRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tag, outbound, domains, domainKeywords, ipCidrs }: { tag: string; outbound: string; domains?: string[]; domainKeywords?: string[]; ipCidrs?: string[] }) =>
      api.addCustomRule(tag, outbound, domains, domainKeywords, ipCidrs),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ruleKeys.all });
    },
  });
}

export function useDeleteCustomRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deleteCustomRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ruleKeys.all });
    },
  });
}
