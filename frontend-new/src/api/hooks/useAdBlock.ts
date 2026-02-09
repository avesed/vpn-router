import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { toast } from "sonner";
import type { AdBlockRuleSetCreateRequest } from "../../types";

export function useAdBlockRules(category?: string) {
  return useQuery({
    queryKey: ["adblock", "rules", category],
    queryFn: () => api.getAdBlockRules(category),
  });
}

export function useAddAdBlockRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: AdBlockRuleSetCreateRequest) => api.createAdBlockRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["adblock", "rules"] });
      toast.success("AdBlock rule added successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to add AdBlock rule: ${error.message}`);
    },
  });
}

export function useUpdateAdBlockRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { tag: string; updates: Partial<AdBlockRuleSetCreateRequest> }) =>
      api.updateAdBlockRule(data.tag, data.updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["adblock", "rules"] });
      toast.success("AdBlock rule updated successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update AdBlock rule: ${error.message}`);
    },
  });
}

export function useDeleteAdBlockRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (tag: string) => api.deleteAdBlockRule(tag),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["adblock", "rules"] });
      toast.success("AdBlock rule deleted successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete AdBlock rule: ${error.message}`);
    },
  });
}

export function useToggleAdBlockRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (tag: string) => api.toggleAdBlockRule(tag),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["adblock", "rules"] });
      toast.success(`Rule ${data.enabled ? "enabled" : "disabled"}`);
    },
    onError: (error: Error) => {
      toast.error(`Failed to toggle AdBlock rule: ${error.message}`);
    },
  });
}

export function useApplyAdBlockRules() {
  return useMutation({
    mutationFn: () => api.applyAdBlockRules(),
    onSuccess: () => {
      toast.success("AdBlock rules applied successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to apply AdBlock rules: ${error.message}`);
    },
  });
}
