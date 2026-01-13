import { useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
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
import {
  MoreHorizontal,
  Trash2,
  Share2,
  RefreshCw,
  Power,
  PowerOff,
} from "lucide-react";
import type { V2RayUser } from "@/types";
import { useDeleteV2RayUser, useUpdateV2RayUser } from "@/api/hooks/useV2RayIngress";
import { V2RayShareDialog } from "./V2RayShareDialog";

interface V2RayUserTableProps {
  users: V2RayUser[];
}

export function V2RayUserTable({ users }: V2RayUserTableProps) {
  const [shareUser, setShareUser] = useState<V2RayUser | null>(null);
  const [deleteUser, setDeleteUser] = useState<V2RayUser | null>(null);
  
  const { mutate: deleteV2RayUser, isPending: isDeleting } = useDeleteV2RayUser();
  const { mutate: updateUser, isPending: isUpdating } = useUpdateV2RayUser();

  const handleDelete = () => {
    if (deleteUser) {
      deleteV2RayUser(deleteUser.id, {
        onSuccess: () => setDeleteUser(null),
      });
    }
  };

  const handleToggleEnabled = (user: V2RayUser) => {
    updateUser({
      id: user.id,
      updates: { enabled: user.enabled ? 0 : 1 },
    });
  };

  const handleResetUuid = (user: V2RayUser) => {
    // Generate a new UUID (this would typically be done server-side, but we can trigger it by sending empty UUID if API supports it,
    // or we can generate one here. Assuming backend handles generation if we don't provide one, or we need to generate one.
    // For now let's assume we need to generate one client side or ask backend.
    // The API `updateV2RayUser` takes `V2RayUserUpdateRequest` which has `uuid`.
    // Let's use crypto.randomUUID()
    updateUser({
      id: user.id,
      updates: { uuid: crypto.randomUUID() },
    });
  };

  return (
    <>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>UUID / Password</TableHead>
              <TableHead>Flow</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                  No users found. Add one to get started.
                </TableCell>
              </TableRow>
            ) : (
              users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">
                    <div className="flex flex-col">
                      <span>{user.name}</span>
                      {user.email && (
                        <span className="text-xs text-muted-foreground">{user.email}</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={user.enabled ? "default" : "secondary"}>
                      {user.enabled ? "Active" : "Disabled"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <code className="bg-muted px-1 py-0.5 rounded text-xs font-mono">
                      {user.uuid || user.password || "N/A"}
                    </code>
                  </TableCell>
                  <TableCell>
                    {user.flow ? (
                      <Badge variant="outline">{user.flow}</Badge>
                    ) : (
                      <span className="text-muted-foreground text-xs">None</span>
                    )}
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
                        <DropdownMenuItem onClick={() => setShareUser(user)}>
                          <Share2 className="mr-2 h-4 w-4" />
                          Share / QR Code
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleToggleEnabled(user)} disabled={isUpdating}>
                          {user.enabled ? (
                            <>
                              <PowerOff className="mr-2 h-4 w-4" />
                              Disable
                            </>
                          ) : (
                            <>
                              <Power className="mr-2 h-4 w-4" />
                              Enable
                            </>
                          )}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleResetUuid(user)} disabled={isUpdating}>
                          <RefreshCw className="mr-2 h-4 w-4" />
                          Reset UUID
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-destructive focus:text-destructive"
                          onClick={() => setDeleteUser(user)}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete User
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <V2RayShareDialog
        user={shareUser}
        open={!!shareUser}
        onOpenChange={(open) => !open && setShareUser(null)}
      />

      <AlertDialog open={!!deleteUser} onOpenChange={(open) => !open && setDeleteUser(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete the user <strong>{deleteUser?.name}</strong>.
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
    </>
  );
}
