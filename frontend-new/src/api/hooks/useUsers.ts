import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type {
  User,
  UserCreateRequest,
  UserUpdateRequest,
  UserQuota,
  UserQuotaUpdateRequest,
  UserListResponse
} from "../../types";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";

export function useUsers() {
  return useQuery<UserListResponse>({
    queryKey: ["users"],
    queryFn: api.getUsers,
  });
}

export function useUser(id: number) {
  return useQuery<{ user: User }>({
    queryKey: ["users", id],
    queryFn: () => api.getUser(id),
    enabled: !!id,
  });
}

export function useCreateUser() {
  const queryClient = useQueryClient();
  const { t } = useTranslation();

  return useMutation({
    mutationFn: (data: UserCreateRequest) => api.createUser(data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      toast.success(t("users.createSuccess", { name: data.user.username }));
    },
    onError: (error: Error) => {
      toast.error(`${t("users.createFailed")}: ${error.message}`);
    },
  });
}

export function useUpdateUser() {
  const queryClient = useQueryClient();
  const { t } = useTranslation();

  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: UserUpdateRequest }) =>
      api.updateUser(id, data),
    onSuccess: (data, { id }) => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      queryClient.invalidateQueries({ queryKey: ["users", id] });
      toast.success(t("users.updateSuccess", { name: data.user.username }));
    },
    onError: (error: Error) => {
      toast.error(`${t("users.updateFailed")}: ${error.message}`);
    },
  });
}

export function useDeleteUser() {
  const queryClient = useQueryClient();
  const { t } = useTranslation();

  return useMutation({
    mutationFn: (id: number) => api.deleteUser(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      toast.success(t("users.deleteSuccess", { name: "" }));
    },
    onError: (error: Error) => {
      toast.error(`${t("users.deleteFailed")}: ${error.message}`);
    },
  });
}

export function useUserQuota(id: number) {
  return useQuery<{ quota: UserQuota }>({
    queryKey: ["users", id, "quota"],
    queryFn: () => api.getUserQuota(id),
    enabled: !!id,
  });
}

export function useUpdateUserQuota() {
  const queryClient = useQueryClient();
  const { t } = useTranslation();

  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: UserQuotaUpdateRequest }) =>
      api.updateUserQuota(id, data),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ["users", id, "quota"] });
      toast.success(t("users.updateSuccess", { name: "" }));
    },
    onError: (error: Error) => {
      toast.error(`${t("users.updateFailed")}: ${error.message}`);
    },
  });
}
