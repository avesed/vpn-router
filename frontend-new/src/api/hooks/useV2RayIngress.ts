import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { toast } from "sonner";
import type { V2RayInboundUpdateRequest, V2RayUserCreateRequest, V2RayUserUpdateRequest } from "../../types";

export function useV2RayIngressConfig() {
  return useQuery({
    queryKey: ["v2ray-ingress", "config"],
    queryFn: () => api.getV2RayInbound(),
  });
}

export function useUpdateV2RayIngressConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: V2RayInboundUpdateRequest) => api.updateV2RayInbound(data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["v2ray-ingress", "config"] });
      if (data.auto_generated_short_id) {
        toast.success(`V2Ray ingress updated. Auto-generated Short ID: ${data.auto_generated_short_id}`);
      } else {
        toast.success("V2Ray ingress configuration updated");
      }
    },
    onError: (error: Error) => {
      toast.error(`Failed to update V2Ray ingress: ${error.message}`);
    },
  });
}

export function useV2RayUsers() {
  return useQuery({
    queryKey: ["v2ray-ingress", "users"],
    queryFn: async () => {
      const response = await api.getV2RayInbound();
      return response.users;
    },
  });
}

export function useAddV2RayUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: V2RayUserCreateRequest) => api.addV2RayUser(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["v2ray-ingress", "config"] });
      queryClient.invalidateQueries({ queryKey: ["v2ray-ingress", "users"] });
      toast.success("User added successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to add user: ${error.message}`);
    },
  });
}

export function useUpdateV2RayUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { id: number; updates: V2RayUserUpdateRequest }) =>
      api.updateV2RayUser(data.id, data.updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["v2ray-ingress", "config"] });
      queryClient.invalidateQueries({ queryKey: ["v2ray-ingress", "users"] });
      toast.success("User updated successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update user: ${error.message}`);
    },
  });
}

export function useDeleteV2RayUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteV2RayUser(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["v2ray-ingress", "config"] });
      queryClient.invalidateQueries({ queryKey: ["v2ray-ingress", "users"] });
      toast.success("User deleted successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete user: ${error.message}`);
    },
  });
}

export function useGetV2RayUserUri() {
  return useMutation({
    mutationFn: (id: number) => api.getV2RayUserShareUri(id),
  });
}

export function useGetV2RayUserQrCode() {
  return useMutation({
    mutationFn: (id: number) => api.getV2RayUserQRCode(id),
  });
}

export function useGenerateRealityKeys() {
  return useMutation({
    mutationFn: () => api.generateRealityKeys(),
  });
}

export function useV2RayIngressOutbound() {
  return useQuery({
    queryKey: ["ingress", "v2ray", "outbound"],
    queryFn: () => api.getV2RayIngressOutbound(),
  });
}

export function useSetV2RayIngressOutbound() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (outbound: string | null) => api.setV2RayIngressOutbound(outbound),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ingress", "v2ray", "outbound"] });
      toast.success("V2Ray ingress outbound updated");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update V2Ray ingress outbound: ${error.message}`);
    },
  });
}

// VLESS-WG Bridge Stats (from rust-router)
export function useVlessBridgeStatus() {
  return useQuery({
    queryKey: ["vless-bridge", "status"],
    queryFn: () => api.getVlessBridgeStatus(),
    refetchInterval: 5000, // Update every 5 seconds
  });
}
