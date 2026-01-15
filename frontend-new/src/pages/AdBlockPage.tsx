import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  useAdBlockRules,
  useAddAdBlockRule,
  useDeleteAdBlockRule,
  useToggleAdBlockRule,
  useApplyAdBlockRules,
} from "@/api/hooks/useAdBlock";
import { Loader2, Plus, MoreHorizontal, Trash2, Play, Shield } from "lucide-react";
import type { AdBlockRuleSet } from "@/types";

const addRuleSchema = z.object({
  tag: z.string().min(1, "Tag is required").regex(/^[a-zA-Z0-9_-]+$/, "Tag can only contain letters, numbers, underscores and dashes"),
  name: z.string().min(1, "Name is required"),
  url: z.string().url("Invalid URL"),
  format: z.enum(["adblock", "hosts", "domains"]),
  category: z.string().default("general"),
  description: z.string().optional(),
});

interface AddRuleForm {
  tag: string;
  name: string;
  url: string;
  format: "adblock" | "hosts" | "domains";
  category: string;
  description?: string;
}

export default function AdBlockPage() {
  const { t } = useTranslation();
  const { data: rulesData, isLoading: isLoadingRules } = useAdBlockRules();
  const { mutate: addRule, isPending: isAdding } = useAddAdBlockRule();
  const { mutate: deleteRule, isPending: isDeleting } = useDeleteAdBlockRule();
  const { mutate: toggleRule, isPending: isToggling } = useToggleAdBlockRule();
  const { mutate: applyRules, isPending: isApplying } = useApplyAdBlockRules();

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<AdBlockRuleSet | null>(null);

  const formatLabels: Record<string, string> = {
    adblock: t("adblock.formatAdblock"),
    hosts: t("adblock.formatHosts"),
    domains: t("adblock.formatDomains"),
  };

  const categoryLabels: Record<string, string> = {
    general: t("adblock.categories.general"),
    privacy: t("adblock.categories.privacy"),
    regional: t("adblock.categories.regional"),
    security: t("adblock.categories.security"),
    antiadblock: t("adblock.categories.antiadblock"),
  };

  const {
    register,
    handleSubmit,
    setValue,
    reset,
    formState: { errors },
  } = useForm<AddRuleForm>({
    resolver: zodResolver(addRuleSchema) as any,
    defaultValues: {
      format: "adblock",
      category: "general",
    },
  });

  const onAddSubmit = (data: AddRuleForm) => {
    addRule(data, {
      onSuccess: () => {
        reset();
        setIsAddOpen(false);
      },
    });
  };

  const handleDelete = () => {
    if (deleteTarget) {
      deleteRule(deleteTarget.tag, {
        onSuccess: () => setDeleteTarget(null),
      });
    }
  };

  if (isLoadingRules) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("adblock.title")}</h1>
          <p className="text-muted-foreground">{t("adblock.subtitle")}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => applyRules()} disabled={isApplying}>
            {isApplying ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Play className="mr-2 h-4 w-4" />
            )}
            {t("adblock.apply")}
          </Button>
          <Button onClick={() => setIsAddOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            {t("adblock.addRule")}
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">{t("adblock.totalRules")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{rulesData?.total || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">{t("adblock.enabledRules")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{rulesData?.enabled_count || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">{t("common.status")}</CardTitle>
          </CardHeader>
          <CardContent>
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-green-500" />
                <div className="text-2xl font-bold">{t("common.enabled")}</div>
              </div>

          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("adblock.ruleSetsTitle")}</CardTitle>
          <CardDescription>{t("adblock.ruleSetsDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
                <TableRow>
                  <TableHead>{t("adblock.ruleName")}</TableHead>
                  <TableHead>{t("adblock.category")}</TableHead>
                  <TableHead>{t("adblock.format")}</TableHead>
                  <TableHead>{t("common.status")}</TableHead>
                  <TableHead className="text-right">{t("common.actions")}</TableHead>
                </TableRow>

            </TableHeader>
            <TableBody>
              {rulesData?.rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                    {t("adblock.noRules")}
                  </TableCell>
                </TableRow>
              ) : (
                rulesData?.rules.map((rule) => (
                  <TableRow key={rule.tag}>
                    <TableCell className="font-medium">
                      <div className="flex flex-col">
                        <span>{rule.name}</span>
                        <span className="text-xs text-muted-foreground truncate max-w-[300px]">
                          {rule.url}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="capitalize">
                        {categoryLabels[rule.category] ?? rule.category}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="capitalize">
                        {formatLabels[rule.format] ?? rule.format}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={!!rule.enabled}
                        onCheckedChange={() => toggleRule(rule.tag)}
                        disabled={isToggling}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" className="h-8 w-8 p-0">
                            <span className="sr-only">{t("common.actions")}</span>
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuLabel>{t("common.actions")}</DropdownMenuLabel>
                          <DropdownMenuItem
                            className="text-destructive focus:text-destructive"
                            onClick={() => setDeleteTarget(rule)}
                          >
                            <Trash2 className="mr-2 h-4 w-4" />
                            {t("common.delete")}
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={isAddOpen} onOpenChange={setIsAddOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("adblock.addRule")}</DialogTitle>
            <DialogDescription>{t("adblock.addRuleDescription")}</DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit(onAddSubmit)} className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="tag">{t("adblock.ruleTag")}</Label>
              <Input
                id="tag"
                placeholder={t("adblock.ruleTagPlaceholder")}
                {...register("tag")}
              />
              {errors.tag && (
                <p className="text-sm text-destructive">{errors.tag.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="name">{t("adblock.ruleName")}</Label>
              <Input
                id="name"
                placeholder={t("adblock.ruleNamePlaceholder")}
                {...register("name")}
              />
              {errors.name && (
                <p className="text-sm text-destructive">{errors.name.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="url">{t("adblock.ruleUrl")}</Label>
              <Input
                id="url"
                placeholder={t("adblock.ruleUrlPlaceholder")}
                {...register("url")}
              />
              {errors.url && (
                <p className="text-sm text-destructive">{errors.url.message}</p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="format">{t("adblock.format")}</Label>
                <Select
                  onValueChange={(value) => setValue("format", value as "adblock" | "hosts" | "domains")}
                  defaultValue="adblock"
                >
                  <SelectTrigger>
                    <SelectValue
                      placeholder={t("common.selectPlaceholder", { item: t("adblock.format") })}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="adblock">{t("adblock.formatAdblock")}</SelectItem>
                    <SelectItem value="hosts">{t("adblock.formatHosts")}</SelectItem>
                    <SelectItem value="domains">{t("adblock.formatDomains")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="category">{t("adblock.category")}</Label>
                <Select
                  onValueChange={(value) => setValue("category", value)}
                  defaultValue="general"
                >
                  <SelectTrigger>
                    <SelectValue
                      placeholder={t("common.selectPlaceholder", { item: t("adblock.category") })}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="general">{t("adblock.categories.general")}</SelectItem>
                    <SelectItem value="privacy">{t("adblock.categories.privacy")}</SelectItem>
                    <SelectItem value="regional">{t("adblock.categories.regional")}</SelectItem>
                    <SelectItem value="security">{t("adblock.categories.security")}</SelectItem>
                    <SelectItem value="antiadblock">{t("adblock.categories.antiadblock")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="description">{t("common.description")}</Label>
              <Input
                id="description"
                placeholder={t("adblock.descriptionPlaceholder")}
                {...register("description")}
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setIsAddOpen(false)}>
                {t("common.cancel")}
              </Button>
              <Button type="submit" disabled={isAdding}>
                {isAdding && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("adblock.addRule")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("common.confirm")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("adblock.confirmDelete", { tag: deleteTarget?.name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={isDeleting}
            >
              {isDeleting ? t("common.deleting") : t("common.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
