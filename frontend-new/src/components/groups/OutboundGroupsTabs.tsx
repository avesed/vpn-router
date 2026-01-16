import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  useOutboundGroups,
  useCreateOutboundGroup,
  useUpdateOutboundGroup,
  useDeleteOutboundGroup,
  useTriggerHealthCheck
} from "../../api/hooks/useOutboundGroups";
import { GroupCard } from "./GroupCard";
import { GroupCreateDialog } from "./GroupCreateDialog";
import { Button } from "../ui/button";
import { Plus, Loader2, Scale } from "lucide-react";
import { toast } from "sonner";
import type { OutboundGroup, OutboundGroupType } from "../../types";

export function OutboundGroupsTabs() {
  const { t } = useTranslation();
  const { data, isLoading, error } = useOutboundGroups();
  const createGroup = useCreateOutboundGroup();
  const updateGroup = useUpdateOutboundGroup();
  const deleteGroup = useDeleteOutboundGroup();
  const triggerHealthCheck = useTriggerHealthCheck();

  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingGroup, setEditingGroup] = useState<OutboundGroup | null>(null);
  const [checkingHealthTag, setCheckingHealthTag] = useState<string | null>(null);

  const groups = data?.groups || [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-2">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <p className="text-destructive font-medium">{t("common.error")}</p>
          <p className="text-sm text-muted-foreground mt-1">{error.message}</p>
        </div>
      </div>
    );
  }

  const handleCreate = async (formData: {
    tag: string;
    description?: string;
    type: OutboundGroupType;
    members: string[];
    weights?: Record<string, number>;
    health_check_url?: string;
    health_check_interval?: number;
    health_check_timeout?: number;
  }) => {
    try {
      await createGroup.mutateAsync(formData);
      toast.success(t("groups.groupCreated", { tag: formData.tag }));
      setShowCreateDialog(false);
    } catch (err) {
      toast.error(t("groups.saveFailed"));
      throw err;
    }
  };

  const handleUpdate = async (formData: {
    tag: string;
    description?: string;
    type: OutboundGroupType;
    members: string[];
    weights?: Record<string, number>;
    health_check_url?: string;
    health_check_interval?: number;
    health_check_timeout?: number;
  }) => {
    if (!editingGroup) return;
    try {
      await updateGroup.mutateAsync({
        tag: editingGroup.tag,
        data: {
          description: formData.description,
          members: formData.members,
          weights: formData.weights,
          health_check_url: formData.health_check_url,
          health_check_interval: formData.health_check_interval,
          health_check_timeout: formData.health_check_timeout,
        }
      });
      toast.success(t("groups.groupUpdated", { tag: editingGroup.tag }));
      setEditingGroup(null);
    } catch (err) {
      toast.error(t("groups.saveFailed"));
      throw err;
    }
  };

  const handleDelete = async (tag: string) => {
    if (!confirm(t("groups.deleteGroupConfirm", { tag }))) return;

    try {
      await deleteGroup.mutateAsync(tag);
      toast.success(t("groups.groupDeleted", { tag }));
    } catch (err) {
      toast.error(t("groups.deleteFailed"));
    }
  };

  const handleHealthCheck = async (tag: string) => {
    setCheckingHealthTag(tag);
    try {
      await triggerHealthCheck.mutateAsync(tag);
      toast.success(t("groups.healthCheckComplete"));
    } catch (err) {
      toast.error(t("groups.healthCheckFailed"));
    } finally {
      setCheckingHealthTag(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">{t("groups.title")}</h2>
          <p className="text-sm text-muted-foreground">{t("groups.subtitle")}</p>
        </div>
        <Button onClick={() => setShowCreateDialog(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t("groups.addGroup")}
        </Button>
      </div>

      {groups.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 border border-dashed rounded-lg">
          <Scale className="h-12 w-12 text-muted-foreground mb-4" />
          <p className="text-lg font-medium text-muted-foreground">{t("groups.noGroups")}</p>
          <p className="text-sm text-muted-foreground mt-1">{t("groups.noGroupsHint")}</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {groups.map((group) => (
            <GroupCard
              key={group.tag}
              group={group}
              onEdit={setEditingGroup}
              onDelete={handleDelete}
              onHealthCheck={handleHealthCheck}
              isCheckingHealth={checkingHealthTag === group.tag}
            />
          ))}
        </div>
      )}

      {/* Create Dialog */}
      <GroupCreateDialog
        open={showCreateDialog}
        onOpenChange={setShowCreateDialog}
        onSubmit={handleCreate}
        isSubmitting={createGroup.isPending}
      />

      {/* Edit Dialog */}
      <GroupCreateDialog
        open={!!editingGroup}
        onOpenChange={(open) => !open && setEditingGroup(null)}
        editGroup={editingGroup}
        onSubmit={handleUpdate}
        isSubmitting={updateGroup.isPending}
      />
    </div>
  );
}
