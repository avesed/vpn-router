import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { toast } from "sonner";

export function useIngressConfig() {
  return useQuery({
    queryKey: ["ingress", "config"],
    queryFn: () => api.getIngress(),
  });
}

export function useIngressSubnet() {
  return useQuery({
    queryKey: ["ingress", "subnet"],
    queryFn: () => api.getIngressSubnet(),
  });
}

export function useUpdateIngressSubnet() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { address: string; migratePeers: boolean }) =>
      api.updateIngressSubnet(data.address, data.migratePeers),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ingress", "subnet"] });
      queryClient.invalidateQueries({ queryKey: ["ingress", "config"] });
      toast.success("Subnet configuration updated");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update subnet: ${error.message}`);
    },
  });
}

export function useIngressSettings() {
  return useQuery({
    queryKey: ["ingress", "settings"],
    queryFn: () => api.getSettings(),
  });
}

export function useUpdateIngressSettings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (serverEndpoint: string) => api.updateSettings(serverEndpoint),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ingress", "settings"] });
      queryClient.invalidateQueries({ queryKey: ["ingress", "config"] });
      toast.success("Settings updated");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update settings: ${error.message}`);
    },
  });
}

export function useDetectIp() {
  return useMutation({
    mutationFn: () => api.detectIp(),
  });
}

export function useAddIngressClient() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; publicKey?: string; allowLan?: boolean; defaultOutbound?: string }) =>
      api.addIngressPeer(data.name, data.publicKey, data.allowLan, data.defaultOutbound),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ingress", "config"] });
      toast.success("Client added successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to add client: ${error.message}`);
    },
  });
}

export function useUpdateIngressClient() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; updates: { name?: string; default_outbound?: string | null } }) =>
      api.updateIngressPeer(data.name, data.updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ingress", "config"] });
      toast.success("Client updated successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update client: ${error.message}`);
    },
  });
}

export function useDeleteIngressClient() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.deleteIngressPeer(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ingress", "config"] });
      toast.success("Client deleted successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete client: ${error.message}`);
    },
  });
}

export function useGetClientConfig() {
  return useMutation({
    mutationFn: (data: { name: string; privateKey?: string }) =>
      api.getIngressPeerConfig(data.name, data.privateKey),
  });
}

export function useGetClientQrCode() {
  return useMutation({
    mutationFn: (data: { name: string; privateKey?: string }) =>
      api.getIngressPeerQrcode(data.name, data.privateKey),
  });
}

export function useIngressOutbound() {
  return useQuery({
    queryKey: ["ingress", "wireguard", "outbound"],
    queryFn: () => api.getWireGuardIngressOutbound(),
  });
}

export function useSetIngressOutbound() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (outbound: string | null) => api.setWireGuardIngressOutbound(outbound),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ingress", "wireguard", "outbound"] });
      toast.success("Ingress outbound updated");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update ingress outbound: ${error.message}`);
    },
  });
}
