import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { toast } from "sonner";

export function usePIAStatus() {
  return useQuery({
    queryKey: ["pia", "status"],
    queryFn: () => api.getPiaCredentialsStatus(),
  });
}

export function usePIALogin() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { username: string; password: string }) =>
      api.piaLogin(data.username, data.password),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ["pia", "status"] });
      toast.success(response.message || "Logged in to PIA successfully");
      if (response.reload?.success) {
        toast.info(response.reload.message);
      }
    },
    onError: (error: Error) => {
      toast.error(`PIA login failed: ${error.message}`);
    },
  });
}

export function usePIARegions() {
  return useQuery({
    queryKey: ["pia", "regions"],
    queryFn: () => api.getPiaRegions(),
  });
}

export function useAddPIALine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { tag: string; description: string; regionId: string; customDns?: string }) =>
      api.createProfile(data.tag, data.description, data.regionId, data.customDns),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["egress", "all"] });
      toast.success("PIA line added successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to add PIA line: ${error.message}`);
    },
  });
}
