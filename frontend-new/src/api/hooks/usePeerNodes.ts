import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type { 
  PeerNode, 
  PeerNodeCreateRequest, 
  PeerNodeUpdateRequest,
  PeerNodeConnectResponse,
  PeerNodeDisconnectResponse,
  EnableInboundResponse,
  DisableInboundResponse
} from "../../types";
import { toast } from "sonner";

export function usePeerNodes() {
  return useQuery<{ nodes: PeerNode[] }>({
    queryKey: ["peers"],
    queryFn: api.getPeerNodes,
  });
}

export function usePeerNode(tag: string) {
  return useQuery<PeerNode>({
    queryKey: ["peers", tag],
    queryFn: () => api.getPeerNode(tag),
    enabled: !!tag,
  });
}

export function useCreatePeerNode() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: PeerNodeCreateRequest) => api.createPeerNode(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["peers"] });
      toast.success("Peer node created successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to create peer node: ${error.message}`);
    },
  });
}

export function useUpdatePeerNode() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tag, data }: { tag: string; data: PeerNodeUpdateRequest }) => 
      api.updatePeerNode(tag, data),
    onSuccess: (_, { tag }) => {
      queryClient.invalidateQueries({ queryKey: ["peers"] });
      queryClient.invalidateQueries({ queryKey: ["peers", tag] });
      toast.success("Peer node updated successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to update peer node: ${error.message}`);
    },
  });
}

export function useDeletePeerNode() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (tag: string) => api.deletePeerNode(tag),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["peers"] });
      toast.success("Peer node deleted successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete peer node: ${error.message}`);
    },
  });
}

export function useConnectPeerNode() {
  const queryClient = useQueryClient();
  return useMutation<PeerNodeConnectResponse, Error, string>({
    mutationFn: (tag: string) => api.connectPeerNode(tag),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["peers"] });
      queryClient.invalidateQueries({ queryKey: ["peers", data.tag] });
      toast.success(`Connected to ${data.tag}`);
    },
    onError: (error: Error) => {
      toast.error(`Failed to connect: ${error.message}`);
    },
  });
}

export function useDisconnectPeerNode() {
  const queryClient = useQueryClient();
  return useMutation<PeerNodeDisconnectResponse, Error, string>({
    mutationFn: (tag: string) => api.disconnectPeerNode(tag),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["peers"] });
      queryClient.invalidateQueries({ queryKey: ["peers", data.tag] });
      toast.success(`Disconnected from ${data.tag}`);
    },
    onError: (error: Error) => {
      toast.error(`Failed to disconnect: ${error.message}`);
    },
  });
}

export function useEnablePeerInbound() {
  const queryClient = useQueryClient();
  return useMutation<EnableInboundResponse, Error, { tag: string; port?: number }>({
    mutationFn: ({ tag, port }) => api.enablePeerInbound(tag, port),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["peers"] });
      queryClient.invalidateQueries({ queryKey: ["peers", data.tag] });
      toast.success(`Inbound enabled for ${data.tag} on port ${data.inbound_port}`);
    },
    onError: (error: Error) => {
      toast.error(`Failed to enable inbound: ${error.message}`);
    },
  });
}

export function useDisablePeerInbound() {
  const queryClient = useQueryClient();
  return useMutation<DisableInboundResponse, Error, string>({
    mutationFn: (tag: string) => api.disablePeerInbound(tag),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["peers"] });
      queryClient.invalidateQueries({ queryKey: ["peers", data.tag] });
      toast.success(`Inbound disabled for ${data.tag}`);
    },
    onError: (error: Error) => {
      toast.error(`Failed to disable inbound: ${error.message}`);
    },
  });
}
