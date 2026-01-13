import { useMutation } from "@tanstack/react-query";
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
  return useMutation<ImportPairRequestResponse, Error, ImportPairRequestRequest>({
    mutationFn: (data) => api.importPairRequest(data),
    onError: (error: Error) => {
      toast.error(`Failed to import pair request: ${error.message}`);
    },
  });
}

export function useCompletePairing() {
  return useMutation<CompletePairingResponse, Error, CompletePairingRequest>({
    mutationFn: (data) => api.completePairing(data),
    onError: (error: Error) => {
      toast.error(`Failed to complete pairing: ${error.message}`);
    },
  });
}
