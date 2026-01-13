import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { toast } from "sonner";

export function useBackupStatus() {
  return useQuery({
    queryKey: ["backup", "status"],
    queryFn: () => api.getBackupStatus(),
  });
}

export function useExportBackup() {
  return useMutation({
    mutationFn: (password: string) => api.exportBackup(password),
    onSuccess: () => {
      toast.success("Backup exported successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to export backup: ${error.message}`);
    },
  });
}

export function useImportBackup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { data: string; password: string }) =>
      api.importBackup(data.data, data.password),
    onSuccess: (response) => {
      queryClient.invalidateQueries();
      toast.success(response.message || "Backup imported successfully");
      // Reload page after successful import to ensure all state is fresh
      setTimeout(() => {
        window.location.reload();
      }, 2000);
    },
    onError: (error: Error) => {
      toast.error(`Failed to import backup: ${error.message}`);
    },
  });
}
