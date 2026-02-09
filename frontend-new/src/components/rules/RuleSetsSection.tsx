import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { RuleSet, RuleSetStatus } from "../../types";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "../ui/collapsible";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { Switch } from "../ui/switch";
import { Label } from "../ui/label";
import { Input } from "../ui/input";
import {
  ChevronDown,
  ChevronRight,
  Trash2,
  RefreshCw,
  Package,
  Loader2,
  Pencil,
} from "lucide-react";
import {
  useUpdateRuleSet,
  useDeleteRuleSet,
  useReloadRuleSet,
} from "../../api/hooks/useRules";
import { toast } from "sonner";

interface RuleSetsSectionProps {
  ruleSets: RuleSet[];
  availableOutbounds: string[];
}

export function RuleSetsSection({ ruleSets, availableOutbounds }: RuleSetsSectionProps) {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(ruleSets.length > 0);
  const [editingRuleSet, setEditingRuleSet] = useState<RuleSet | null>(null);
  const [newName, setNewName] = useState<string>("");
  const [newOutbound, setNewOutbound] = useState<string>("");
  const updateRuleSet = useUpdateRuleSet();
  const deleteRuleSet = useDeleteRuleSet();
  const reloadRuleSet = useReloadRuleSet();

  const handleToggleEnabled = (ruleSet: RuleSet) => {
    toast.promise(
      updateRuleSet.mutateAsync({ id: ruleSet.id, enabled: !ruleSet.enabled }),
      {
        loading: t("common.saving"),
        success: ruleSet.enabled
          ? t("ruleSets.disabled", { id: ruleSet.id })
          : t("ruleSets.enabled", { id: ruleSet.id }),
        error: t("common.saveFailed"),
      }
    );
  };

  const handleDelete = (ruleSet: RuleSet) => {
    if (!confirm(t("ruleSets.confirmDelete", { id: ruleSet.id }))) return;
    toast.promise(deleteRuleSet.mutateAsync(ruleSet.id), {
      loading: t("common.deleting"),
      success: t("ruleSets.deleted", { id: ruleSet.id }),
      error: t("common.deleteFailed"),
    });
  };

  const handleReload = (ruleSet: RuleSet) => {
    toast.promise(reloadRuleSet.mutateAsync(ruleSet.id), {
      loading: t("ruleSets.reloading", { id: ruleSet.id }),
      success: t("ruleSets.reloaded", { id: ruleSet.id }),
      error: t("ruleSets.reloadFailed"),
    });
  };

  const handleEdit = (ruleSet: RuleSet) => {
    setEditingRuleSet(ruleSet);
    setNewName(ruleSet.name);
    setNewOutbound(ruleSet.outbound);
  };

  const handleSaveEdit = () => {
    if (!editingRuleSet || !newOutbound) return;

    // Only include name if it changed
    const updates: { id: string; name?: string; outbound?: string } = {
      id: editingRuleSet.id,
    };
    if (newName !== editingRuleSet.name) {
      updates.name = newName;
    }
    if (newOutbound !== editingRuleSet.outbound) {
      updates.outbound = newOutbound;
    }

    toast.promise(
      updateRuleSet.mutateAsync(updates),
      {
        loading: t("common.saving"),
        success: t("ruleSets.updated", { id: editingRuleSet.id }),
        error: t("common.saveFailed"),
      }
    );
    setEditingRuleSet(null);
  };

  const getStatusBadge = (status: RuleSetStatus) => {
    switch (status) {
      case "pending":
        return (
          <Badge variant="secondary" className="gap-1">
            <span className="text-muted-foreground">...</span>
            {t("ruleSets.status.pending")}
          </Badge>
        );
      case "loading":
        return (
          <Badge variant="secondary" className="gap-1">
            <Loader2 className="h-3 w-3 animate-spin" />
            {t("ruleSets.status.loading")}
          </Badge>
        );
      case "loaded":
        return (
          <Badge variant="default" className="gap-1 bg-green-600">
            <span className="text-green-100">&#10003;</span>
            {t("ruleSets.status.loaded")}
          </Badge>
        );
      case "error":
        return (
          <Badge variant="destructive" className="gap-1">
            <span>&#10007;</span>
            {t("ruleSets.status.error")}
          </Badge>
        );
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const getTypeBadge = (type: string) => {
    return (
      <Badge variant="outline">
        {type === "ip" ? "IP" : t("ruleSets.typeDomain")}
      </Badge>
    );
  };

  const formatCount = (count: number): string => {
    if (count >= 1000000) {
      return `${(count / 1000000).toFixed(1)}M`;
    }
    if (count >= 1000) {
      return `${(count / 1000).toFixed(1)}K`;
    }
    return count.toLocaleString();
  };

  if (ruleSets.length === 0) {
    return null;
  }

  return (
    <>
      <Collapsible open={isOpen} onOpenChange={setIsOpen} className="space-y-2">
        <div className="flex items-center justify-between">
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="gap-2 p-0 hover:bg-transparent">
              {isOpen ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
              <Package className="h-5 w-5" />
              <span className="text-lg font-semibold">
                {t("ruleSets.title")} ({ruleSets.length})
              </span>
            </Button>
          </CollapsibleTrigger>
        </div>

        <CollapsibleContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">{t("common.enabled")}</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead>{t("common.name")}</TableHead>
                  <TableHead>{t("common.type")}</TableHead>
                  <TableHead className="text-right">
                    {t("ruleSets.ruleCount")}
                  </TableHead>
                  <TableHead>{t("rules.outbound")}</TableHead>
                  <TableHead>{t("common.status")}</TableHead>
                  <TableHead className="text-right">{t("common.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ruleSets.map((ruleSet) => (
                  <TableRow key={ruleSet.id} className={!ruleSet.enabled ? "opacity-50" : ""}>
                    <TableCell>
                      <Switch
                        checked={ruleSet.enabled}
                        onCheckedChange={() => handleToggleEnabled(ruleSet)}
                        disabled={updateRuleSet.isPending}
                      />
                    </TableCell>
                    <TableCell className="font-medium">{ruleSet.id}</TableCell>
                    <TableCell className="text-muted-foreground">{ruleSet.name}</TableCell>
                    <TableCell>{getTypeBadge(ruleSet.rule_type)}</TableCell>
                    <TableCell className="text-right font-mono">
                      {formatCount(ruleSet.count)}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{ruleSet.outbound}</Badge>
                    </TableCell>
                    <TableCell>{getStatusBadge(ruleSet.status)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleEdit(ruleSet)}
                          title={t("common.edit")}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleReload(ruleSet)}
                          disabled={reloadRuleSet.isPending}
                          title={t("ruleSets.reload")}
                        >
                          <RefreshCw
                            className={`h-4 w-4 ${
                              reloadRuleSet.isPending ? "animate-spin" : ""
                            }`}
                          />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-destructive hover:text-destructive"
                          onClick={() => handleDelete(ruleSet)}
                          disabled={deleteRuleSet.isPending}
                          title={t("common.delete")}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CollapsibleContent>
      </Collapsible>

      {/* Edit Dialog */}
      <Dialog open={!!editingRuleSet} onOpenChange={(open) => !open && setEditingRuleSet(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("ruleSets.editTitle")}</DialogTitle>
            <DialogDescription>
              {t("ruleSets.editDescription", { id: editingRuleSet?.id })}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="name" className="text-right">
                {t("common.name")}
              </Label>
              <Input
                id="name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="col-span-3"
                placeholder={t("ruleSets.namePlaceholder")}
              />
            </div>

            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="outbound" className="text-right">
                {t("rules.outbound")}
              </Label>
              <Select value={newOutbound} onValueChange={setNewOutbound}>
                <SelectTrigger className="col-span-3">
                  <SelectValue placeholder={t("rules.selectOutbound")} />
                </SelectTrigger>
                <SelectContent>
                  {availableOutbounds.map((ob) => (
                    <SelectItem key={ob} value={ob}>
                      {ob}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {editingRuleSet && (
              <div className="grid grid-cols-4 items-center gap-4 text-sm text-muted-foreground">
                <span className="text-right">{t("common.type")}:</span>
                <span className="col-span-3">{editingRuleSet.rule_type === "ip" ? "IP CIDR" : "Domain"}</span>
                <span className="text-right">{t("ruleSets.ruleCount")}:</span>
                <span className="col-span-3">{formatCount(editingRuleSet.count)}</span>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingRuleSet(null)}>
              {t("common.cancel")}
            </Button>
            <Button
              onClick={handleSaveEdit}
              disabled={updateRuleSet.isPending || (newName === editingRuleSet?.name && newOutbound === editingRuleSet?.outbound)}
            >
              {t("common.save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
