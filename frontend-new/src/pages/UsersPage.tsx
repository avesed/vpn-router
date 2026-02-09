import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import {
  useUsers,
  useCreateUser,
  useUpdateUser,
  useDeleteUser,
  useRulesIgnoreSettings,
  useSetRulesIgnoreSettings,
  useSetUserRulesIgnored,
} from "@/api/hooks/useUsers";
import { useAuth } from "@/providers/AuthProvider";
import { api } from "@/api/client";
import type { User, UserCreateRequest, UserUpdateRequest } from "@/types";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Plus,
  Pencil,
  Trash2,
  Shield,
  User as UserIcon,
  Loader2,
  Check,
  X,
  Hourglass,
  AlertTriangle,
} from "lucide-react";
import { toast } from "sonner";

export function UsersPage() {
  const { t } = useTranslation();
  const { user: currentUser } = useAuth();
  const { data, isLoading, refetch } = useUsers();
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();
  const { data: rulesIgnoreSettings, isLoading: loadingRulesIgnore } = useRulesIgnoreSettings();
  const setRulesIgnoreSettings = useSetRulesIgnoreSettings();
  const setUserRulesIgnored = useSetUserRulesIgnored();

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [formData, setFormData] = useState<{
    username: string;
    password: string;
    email: string;
    role: "admin" | "user";
    enabled: boolean;
  }>({
    username: "",
    password: "",
    email: "",
    role: "user",
    enabled: true,
  });

  // Registration settings state
  const [registrationEnabled, setRegistrationEnabled] = useState(false);
  const [defaultRole, setDefaultRole] = useState<"user" | "pending">("pending");
  const [pendingUsers, setPendingUsers] = useState<User[]>([]);
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [approvingUser, setApprovingUser] = useState<number | null>(null);
  const [rejectingUser, setRejectingUser] = useState<number | null>(null);

  // Load registration settings and pending users
  useEffect(() => {
    const loadSettings = async () => {
      try {
        const settings = await api.getRegistrationSettings();
        setRegistrationEnabled(settings.allow_registration);
        setDefaultRole(settings.default_role);

        const pending = await api.getPendingUsers();
        setPendingUsers(pending.users);
      } catch (error) {
        console.error("Failed to load registration settings:", error);
      } finally {
        setLoadingSettings(false);
      }
    };
    loadSettings();
  }, []);

  const handleRegistrationToggle = async (enabled: boolean) => {
    try {
      await api.updateRegistrationSettings({ allow_registration: enabled });
      setRegistrationEnabled(enabled);
      toast.success(t("common.success"));
    } catch (error) {
      console.error("Failed to update registration setting:", error);
      toast.error(error instanceof Error ? error.message : t("common.error"));
    }
  };

  const handleDefaultRoleChange = async (role: "user" | "pending") => {
    try {
      await api.updateRegistrationSettings({ default_role: role });
      setDefaultRole(role);
      toast.success(t("common.success"));
    } catch (error) {
      console.error("Failed to update default role:", error);
      toast.error(error instanceof Error ? error.message : t("common.error"));
    }
  };

  const handleApproveUser = async (userId: number) => {
    setApprovingUser(userId);
    try {
      await api.approveUser(userId);
      setPendingUsers(prev => prev.filter(u => u.id !== userId));
      refetch();
      toast.success(t("users.userApproved"));
    } catch (error) {
      console.error("Failed to approve user:", error);
      toast.error(error instanceof Error ? error.message : t("common.error"));
    } finally {
      setApprovingUser(null);
    }
  };

  const handleRejectUser = async (userId: number) => {
    setRejectingUser(userId);
    try {
      await api.rejectUser(userId);
      setPendingUsers(prev => prev.filter(u => u.id !== userId));
      toast.success(t("users.userRejected"));
    } catch (error) {
      console.error("Failed to reject user:", error);
      toast.error(error instanceof Error ? error.message : t("common.error"));
    } finally {
      setRejectingUser(null);
    }
  };

  const resetForm = () => {
    setFormData({
      username: "",
      password: "",
      email: "",
      role: "user",
      enabled: true,
    });
  };

  const handleCreateOpen = () => {
    resetForm();
    setIsCreateOpen(true);
  };

  const handleEditOpen = (user: User) => {
    setEditingUser(user);
    setFormData({
      username: user.username,
      password: "",
      email: user.email || "",
      role: user.role === "pending" ? "user" : user.role,
      enabled: user.enabled,
    });
  };

  const handleCreate = async () => {
    if (!formData.username || !formData.password) return;

    const request: UserCreateRequest = {
      username: formData.username,
      password: formData.password,
      email: formData.email || undefined,
      role: formData.role,
    };

    await createUser.mutateAsync(request);
    setIsCreateOpen(false);
    resetForm();
  };

  const handleUpdate = async () => {
    if (!editingUser) return;

    const request: UserUpdateRequest = {};
    if (formData.password) request.password = formData.password;
    if (formData.email !== editingUser.email) request.email = formData.email || undefined;
    if (formData.role !== editingUser.role) request.role = formData.role;
    if (formData.enabled !== editingUser.enabled) request.enabled = formData.enabled;

    await updateUser.mutateAsync({ id: editingUser.id, data: request });
    setEditingUser(null);
    resetForm();
  };

  const handleDelete = async (user: User) => {
    await deleteUser.mutateAsync(user.id);
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return t("users.neverLoggedIn");
    return new Date(dateStr).toLocaleString();
  };

  const isCurrentUser = (user: User) => currentUser?.id === user.id;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("users.title")}</h1>
          <p className="text-muted-foreground">{t("users.subtitle")}</p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button onClick={handleCreateOpen}>
              <Plus className="mr-2 h-4 w-4" />
              {t("users.addUser")}
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t("users.addUser")}</DialogTitle>
              <DialogDescription>
                {t("users.roleUserDesc")}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="create-username">{t("users.username")}</Label>
                <Input
                  id="create-username"
                  value={formData.username}
                  onChange={(e) =>
                    setFormData({ ...formData, username: e.target.value })
                  }
                  placeholder={t("users.usernamePlaceholder")}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="create-password">{t("users.password")}</Label>
                <Input
                  id="create-password"
                  type="password"
                  value={formData.password}
                  onChange={(e) =>
                    setFormData({ ...formData, password: e.target.value })
                  }
                  placeholder={t("users.passwordPlaceholder")}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="create-email">{t("users.emailOptional")}</Label>
                <Input
                  id="create-email"
                  type="email"
                  value={formData.email}
                  onChange={(e) =>
                    setFormData({ ...formData, email: e.target.value })
                  }
                  placeholder={t("users.emailPlaceholder")}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="create-role">{t("users.role")}</Label>
                <Select
                  value={formData.role}
                  onValueChange={(value: "admin" | "user") =>
                    setFormData({ ...formData, role: value })
                  }
                >
                  <SelectTrigger id="create-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user">
                      <div className="flex items-center">
                        <UserIcon className="mr-2 h-4 w-4" />
                        {t("users.roleUser")}
                      </div>
                    </SelectItem>
                    <SelectItem value="admin">
                      <div className="flex items-center">
                        <Shield className="mr-2 h-4 w-4" />
                        {t("users.roleAdmin")}
                      </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {formData.role === "admin"
                    ? t("users.roleAdminDesc")
                    : t("users.roleUserDesc")}
                </p>
              </div>
            </div>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => setIsCreateOpen(false)}
              >
                {t("common.cancel")}
              </Button>
              <Button
                onClick={handleCreate}
                disabled={
                  !formData.username ||
                  !formData.password ||
                  createUser.isPending
                }
              >
                {createUser.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                {t("common.create")}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Registration Settings Card */}
      <Card>
        <CardHeader>
          <CardTitle>{t("settings.registrationTitle")}</CardTitle>
          <CardDescription>{t("settings.registrationDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loadingSettings ? (
            <div className="flex items-center justify-center py-4">
              <Loader2 className="h-4 w-4 animate-spin" />
            </div>
          ) : (
            <>
              {/* Registration Toggle */}
              <div className="flex items-center justify-between">
                <Label htmlFor="allow-registration">{t("settings.allowRegistration")}</Label>
                <Switch
                  id="allow-registration"
                  checked={registrationEnabled}
                  onCheckedChange={handleRegistrationToggle}
                />
              </div>

              {/* Default Role Select */}
              <div className="flex items-center justify-between">
                <Label htmlFor="default-role">{t("settings.defaultRole")}</Label>
                <Select value={defaultRole} onValueChange={handleDefaultRoleChange}>
                  <SelectTrigger className="w-[180px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pending">{t("settings.requireApproval")}</SelectItem>
                    <SelectItem value="user">{t("settings.directAccess")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Rules Ignore Settings Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5" />
            {t("users.rulesIgnoreTitle")}
          </CardTitle>
          <CardDescription>{t("users.rulesIgnoreDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loadingRulesIgnore ? (
            <div className="flex items-center justify-center py-4">
              <Loader2 className="h-4 w-4 animate-spin" />
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="ignore-all-rules">{t("users.ignoreAllUserRules")}</Label>
                <p className="text-sm text-muted-foreground">
                  {t("users.ignoreAllUserRulesDesc")}
                </p>
              </div>
              <Switch
                id="ignore-all-rules"
                checked={rulesIgnoreSettings?.ignore_all_user_rules ?? false}
                onCheckedChange={(checked) => {
                  setRulesIgnoreSettings.mutate({ ignore_all_user_rules: checked });
                }}
                disabled={setRulesIgnoreSettings.isPending}
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pending Users Card */}
      {pendingUsers.length > 0 && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Hourglass className="h-5 w-5" />
                {t("users.pendingApproval")}
              </CardTitle>
            </div>
            <Badge variant="secondary">{pendingUsers.length}</Badge>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("users.username")}</TableHead>
                  <TableHead>{t("users.email")}</TableHead>
                  <TableHead>{t("users.createdAt")}</TableHead>
                  <TableHead className="text-right">{t("common.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pendingUsers.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">{user.username}</TableCell>
                    <TableCell>{user.email || "-"}</TableCell>
                    <TableCell>{user.created_at ? new Date(user.created_at).toLocaleDateString() : "-"}</TableCell>
                    <TableCell className="text-right space-x-2">
                      <Button
                        size="sm"
                        onClick={() => handleApproveUser(user.id)}
                        disabled={approvingUser === user.id || rejectingUser === user.id}
                      >
                        {approvingUser === user.id ? (
                          <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                        ) : (
                          <Check className="mr-1 h-4 w-4" />
                        )}
                        {t("users.approve")}
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => handleRejectUser(user.id)}
                        disabled={approvingUser === user.id || rejectingUser === user.id}
                      >
                        {rejectingUser === user.id ? (
                          <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                        ) : (
                          <X className="mr-1 h-4 w-4" />
                        )}
                        {t("users.reject")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Users List Card */}
      <Card>
        <CardHeader>
          <CardTitle>{t("users.title")}</CardTitle>
          <CardDescription>{t("users.subtitle")}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              {t("common.loading")}
            </div>
          ) : !data?.users?.length ? (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <UserIcon className="h-12 w-12 mb-4 opacity-50" />
              <p>{t("users.noUsers")}</p>
              <p className="text-sm">{t("users.noUsersHint")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("users.username")}</TableHead>
                  <TableHead>{t("users.email")}</TableHead>
                  <TableHead>{t("users.role")}</TableHead>
                  <TableHead>{t("users.status")}</TableHead>
                  <TableHead>{t("users.lastLogin")}</TableHead>
                  <TableHead>{t("users.rulesIgnored")}</TableHead>
                  <TableHead className="text-right">{t("common.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">
                      {user.username}
                      {isCurrentUser(user) && (
                        <Badge variant="secondary" className="ml-2">
                          {t("common.you")}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>{user.email || "-"}</TableCell>
                    <TableCell>
                      <Badge
                        variant={user.role === "admin" ? "default" : "outline"}
                      >
                        {user.role === "admin" ? (
                          <Shield className="mr-1 h-3 w-3" />
                        ) : (
                          <UserIcon className="mr-1 h-3 w-3" />
                        )}
                        {t(`users.role${user.role === "admin" ? "Admin" : "User"}`)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={user.enabled ? "default" : "destructive"}>
                        {user.enabled ? t("users.enabled") : t("users.disabled")}
                      </Badge>
                    </TableCell>
                    <TableCell>{formatDate(user.last_login_at)}</TableCell>
                    <TableCell>
                      {user.role === "admin" ? (
                        <span className="text-muted-foreground">-</span>
                      ) : (
                        <Switch
                          checked={user.rules_ignored ?? false}
                          onCheckedChange={(checked) => {
                            setUserRulesIgnored.mutate({
                              userId: user.id,
                              rulesIgnored: checked,
                            });
                          }}
                          disabled={
                            setUserRulesIgnored.isPending ||
                            rulesIgnoreSettings?.ignore_all_user_rules
                          }
                        />
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Dialog
                          open={editingUser?.id === user.id}
                          onOpenChange={(open) => {
                            if (!open) {
                              setEditingUser(null);
                              resetForm();
                            }
                          }}
                        >
                          <DialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleEditOpen(user)}
                            >
                              <Pencil className="h-4 w-4" />
                            </Button>
                          </DialogTrigger>
                          <DialogContent>
                            <DialogHeader>
                              <DialogTitle>{t("users.editUser")}</DialogTitle>
                              <DialogDescription>
                                {t("users.roleUserDesc")}
                              </DialogDescription>
                            </DialogHeader>
                            <div className="space-y-4 py-4">
                              <div className="space-y-2">
                                <Label>{t("users.username")}</Label>
                                <Input value={formData.username} disabled />
                              </div>
                              <div className="space-y-2">
                                <Label htmlFor="edit-password">
                                  {t("users.newPassword")}
                                </Label>
                                <Input
                                  id="edit-password"
                                  type="password"
                                  value={formData.password}
                                  onChange={(e) =>
                                    setFormData({
                                      ...formData,
                                      password: e.target.value,
                                    })
                                  }
                                  placeholder={t("users.newPasswordPlaceholder")}
                                />
                              </div>
                              <div className="space-y-2">
                                <Label htmlFor="edit-email">
                                  {t("users.emailOptional")}
                                </Label>
                                <Input
                                  id="edit-email"
                                  type="email"
                                  value={formData.email}
                                  onChange={(e) =>
                                    setFormData({
                                      ...formData,
                                      email: e.target.value,
                                    })
                                  }
                                  placeholder={t("users.emailPlaceholder")}
                                />
                              </div>
                              <div className="space-y-2">
                                <Label htmlFor="edit-role">{t("users.role")}</Label>
                                <Select
                                  value={formData.role}
                                  onValueChange={(value: "admin" | "user") =>
                                    setFormData({ ...formData, role: value })
                                  }
                                  disabled={isCurrentUser(user)}
                                >
                                  <SelectTrigger id="edit-role">
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value="user">
                                      <div className="flex items-center">
                                        <UserIcon className="mr-2 h-4 w-4" />
                                        {t("users.roleUser")}
                                      </div>
                                    </SelectItem>
                                    <SelectItem value="admin">
                                      <div className="flex items-center">
                                        <Shield className="mr-2 h-4 w-4" />
                                        {t("users.roleAdmin")}
                                      </div>
                                    </SelectItem>
                                  </SelectContent>
                                </Select>
                              </div>
                              <div className="flex items-center justify-between">
                                <Label htmlFor="edit-enabled">
                                  {t("users.status")}
                                </Label>
                                <Switch
                                  id="edit-enabled"
                                  checked={formData.enabled}
                                  onCheckedChange={(checked) =>
                                    setFormData({ ...formData, enabled: checked })
                                  }
                                  disabled={isCurrentUser(user)}
                                />
                              </div>
                            </div>
                            <DialogFooter>
                              <Button
                                variant="outline"
                                onClick={() => {
                                  setEditingUser(null);
                                  resetForm();
                                }}
                              >
                                {t("common.cancel")}
                              </Button>
                              <Button
                                onClick={handleUpdate}
                                disabled={updateUser.isPending}
                              >
                                {updateUser.isPending && (
                                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                )}
                                {t("common.save")}
                              </Button>
                            </DialogFooter>
                          </DialogContent>
                        </Dialog>

                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              disabled={isCurrentUser(user)}
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>
                                {t("users.confirmDeleteTitle")}
                              </AlertDialogTitle>
                              <AlertDialogDescription>
                                {t("users.confirmDeleteMessage")}
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>
                                {t("common.cancel")}
                              </AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => handleDelete(user)}
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                              >
                                {t("common.delete")}
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
