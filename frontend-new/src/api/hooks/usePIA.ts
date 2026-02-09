import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { toast } from "sonner";
import { egressKeys } from "./useEgress";

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
      queryClient.invalidateQueries({ queryKey: ["pia", "profiles"] });
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
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

export function usePIAProfiles() {
  return useQuery({
    queryKey: ["pia", "profiles"],
    queryFn: () => api.getProfiles(),
  });
}

export function useAddPIALine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { tag: string; description: string; regionId: string; customDns?: string }) =>
      api.createProfile(data.tag, data.description, data.regionId, data.customDns),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: ["pia", "profiles"] });
      queryClient.invalidateQueries({ queryKey: ["pia", "status"] });
      // Show the backend message which includes provisioning status
      toast.success(response.message || "PIA line added successfully");
      if (response.provision && !response.provision.success) {
        toast.warning("Profile created but not provisioned. Please login to PIA to configure.");
      }
    },
    onError: (error: Error) => {
      toast.error(`Failed to add PIA line: ${error.message}`);
    },
  });
}

export function useUpdatePIALine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { 
      tag: string; 
      data: { description?: string; region_id?: string; custom_dns?: string } 
    }) => api.updateProfile(data.tag, data.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: ["pia", "profiles"] });
      toast.success("PIA line updated successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update PIA line: ${error.message}`);
    },
  });
}

export function useDeletePIALine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (tag: string) => api.deleteProfile(tag),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: ["pia", "profiles"] });
      toast.success("PIA line deleted successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete PIA line: ${error.message}`);
    },
  });
}

export function useReconnectPIALine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (tag: string) => api.reconnectProfile(tag),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: egressKeys.all });
      queryClient.invalidateQueries({ queryKey: ["pia", "profiles"] });
      queryClient.invalidateQueries({ queryKey: ["pia", "status"] });
      toast.success(response.message || "PIA line reconnected");
      if (response.reload?.success) {
        toast.info(response.reload.message);
      }
    },
    onError: (error: Error) => {
      toast.error(`Failed to reconnect: ${error.message}`);
    },
  });
}
