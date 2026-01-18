import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type { 
  GeneratePairRequestRequest,
  GeneratePairRequestResponse,
  ImportPairRequestRequest,
  ImportPairRequestResponse,
  CompletePairingRequest,
  CompletePairingResponse
} from "../../types";
import { toast } from "sonner";

export function useGeneratePairRequest() {
  return useMutation<GeneratePairRequestResponse, Error, GeneratePairRequestRequest>({
    mutationFn: (data) => api.generatePairRequest(data),
    onError: (error: Error) => {
      toast.error(`Failed to generate pair request: ${error.message}`);
    },
  });
}

export function useImportPairRequest() {
  const queryClient = useQueryClient();
  return useMutation<ImportPairRequestResponse, Error, ImportPairRequestRequest>({
    mutationFn: (data) => api.importPairRequest(data),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ["peers"] });
      }
    },
    onError: (error: Error) => {
      toast.error(`Failed to import pair request: ${error.message}`);
    },
  });
}

export function useCompletePairing() {
  const queryClient = useQueryClient();
  return useMutation<CompletePairingResponse, Error, CompletePairingRequest>({
    mutationFn: (data) => api.completePairing(data),
    onSuccess: (response) => {
      if (response.success) {
        queryClient.invalidateQueries({ queryKey: ["peers"] });
      }
    },
    onError: (error: Error) => {
      toast.error(`Failed to complete pairing: ${error.message}`);
    },
  });
}
