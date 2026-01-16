import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type { OutboundGroupUpdateRequest } from "../../types";

// Query keys for cache management
export const outboundGroupKeys = {
  all: ["outbound-groups"] as const,
  list: (enabledOnly?: boolean) => [...outboundGroupKeys.all, "list", { enabledOnly }] as const,
  detail: (tag: string) => [...outboundGroupKeys.all, "detail", tag] as const,
  availableMembers: ["outbound-groups", "available-members"] as const,
};

// Fetch all outbound groups
export function useOutboundGroups(enabledOnly = false) {
  return useQuery({
    queryKey: outboundGroupKeys.list(enabledOnly),
    queryFn: () => api.getOutboundGroups(enabledOnly),
  });
}

// Fetch a single outbound group
export function useOutboundGroup(tag: string) {
  return useQuery({
    queryKey: outboundGroupKeys.detail(tag),
    queryFn: () => api.getOutboundGroup(tag),
    enabled: !!tag,
  });
}

// Fetch available members for group creation
export function useAvailableMembers() {
  return useQuery({
    queryKey: outboundGroupKeys.availableMembers,
    queryFn: api.getAvailableMembers,
  });
}

// Create a new outbound group
export function useCreateOutboundGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.createOutboundGroup,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: outboundGroupKeys.all });
    },
  });
}

// Update an existing outbound group
export function useUpdateOutboundGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tag, data }: { tag: string; data: OutboundGroupUpdateRequest }) =>
      api.updateOutboundGroup(tag, data),
    onSuccess: (_, { tag }) => {
      queryClient.invalidateQueries({ queryKey: outboundGroupKeys.all });
      queryClient.invalidateQueries({ queryKey: outboundGroupKeys.detail(tag) });
    },
  });
}

// Delete an outbound group
export function useDeleteOutboundGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.deleteOutboundGroup,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: outboundGroupKeys.all });
    },
  });
}

// Trigger health check for a group
export function useTriggerHealthCheck() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.triggerGroupHealthCheck,
    onSuccess: (_, tag) => {
      queryClient.invalidateQueries({ queryKey: outboundGroupKeys.all });
      queryClient.invalidateQueries({ queryKey: outboundGroupKeys.detail(tag) });
    },
  });
}
