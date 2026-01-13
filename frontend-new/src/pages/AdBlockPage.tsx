import { useState } from "react";
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
  category: z.string().default("ads"),
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
  const { data: rulesData, isLoading: isLoadingRules } = useAdBlockRules();
  const { mutate: addRule, isPending: isAdding } = useAddAdBlockRule();
  const { mutate: deleteRule, isPending: isDeleting } = useDeleteAdBlockRule();
  const { mutate: toggleRule, isPending: isToggling } = useToggleAdBlockRule();
  const { mutate: applyRules, isPending: isApplying } = useApplyAdBlockRules();

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<AdBlockRuleSet | null>(null);

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
      category: "ads",
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
          <h1 className="text-3xl font-bold tracking-tight">AdBlock & Privacy</h1>
          <p className="text-muted-foreground">
            Manage DNS-based ad blocking and privacy filters.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => applyRules()} disabled={isApplying}>
            {isApplying ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Play className="mr-2 h-4 w-4" />
            )}
            Apply Changes
          </Button>
          <Button onClick={() => setIsAddOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Add Rule Set
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{rulesData?.total || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Enabled Sets</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{rulesData?.enabled_count || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-green-500" />
              <div className="text-2xl font-bold">Active</div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Rule Sets</CardTitle>
          <CardDescription>
            Configure blocklists for ads, trackers, and malicious domains.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Format</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rulesData?.rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                    No rule sets found. Add one to get started.
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
                        {rule.category}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="capitalize">
                        {rule.format}
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
                            <span className="sr-only">Open menu</span>
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuLabel>Actions</DropdownMenuLabel>
                          <DropdownMenuItem
                            className="text-destructive focus:text-destructive"
                            onClick={() => setDeleteTarget(rule)}
                          >
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
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
            <DialogTitle>Add Rule Set</DialogTitle>
            <DialogDescription>
              Add a new blocklist from a URL.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit(onAddSubmit)} className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="tag">Tag (Unique ID)</Label>
              <Input
                id="tag"
                placeholder="adguard-base"
                {...register("tag")}
              />
              {errors.tag && (
                <p className="text-sm text-destructive">{errors.tag.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                placeholder="AdGuard Base Filter"
                {...register("name")}
              />
              {errors.name && (
                <p className="text-sm text-destructive">{errors.name.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="url">Source URL</Label>
              <Input
                id="url"
                placeholder="https://example.com/list.txt"
                {...register("url")}
              />
              {errors.url && (
                <p className="text-sm text-destructive">{errors.url.message}</p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="format">Format</Label>
                <Select
                  onValueChange={(value) => setValue("format", value as "adblock" | "hosts" | "domains")}
                  defaultValue="adblock"
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select format" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="adblock">AdBlock</SelectItem>
                    <SelectItem value="hosts">Hosts</SelectItem>
                    <SelectItem value="domains">Domains</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="category">Category</Label>
                <Select
                  onValueChange={(value) => setValue("category", value)}
                  defaultValue="ads"
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select category" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ads">Ads</SelectItem>
                    <SelectItem value="privacy">Privacy</SelectItem>
                    <SelectItem value="security">Security</SelectItem>
                    <SelectItem value="parental">Parental</SelectItem>
                    <SelectItem value="other">Other</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="description">Description (Optional)</Label>
              <Input
                id="description"
                placeholder="Blocks ads and trackers"
                {...register("description")}
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setIsAddOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isAdding}>
                {isAdding && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Add Rule Set
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This will remove the rule set <strong>{deleteTarget?.name}</strong>.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={isDeleting}
            >
              {isDeleting ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
