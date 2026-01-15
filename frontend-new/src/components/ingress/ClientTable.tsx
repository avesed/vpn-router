import { useState } from "react";
import { useTranslation } from "react-i18next";
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
  QrCode,
  ArrowDown,
  ArrowUp,
  Settings,
} from "lucide-react";
import type { IngressPeer } from "@/types";
import { formatBytes } from "@/lib/utils";
import { useDeleteIngressClient, useUpdateIngressClient, useIngressOutbound } from "@/api/hooks/useIngress";
import { ClientConfigDialog } from "./ClientConfigDialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";

interface ClientTableProps {
  clients: IngressPeer[];
}

export function ClientTable({ clients }: ClientTableProps) {
  const { t } = useTranslation();
  const [configClient, setConfigClient] = useState<IngressPeer | null>(null);
  const [deleteClient, setDeleteClient] = useState<IngressPeer | null>(null);
  const [editClient, setEditClient] = useState<IngressPeer | null>(null);

  const { mutate: deletePeer, isPending: isDeleting } = useDeleteIngressClient();
  const { mutate: updatePeer, isPending: isUpdating } = useUpdateIngressClient();
  const { data: outboundData } = useIngressOutbound();

  // Helper function to determine if a client is online based on last_handshake
  // WireGuard keepalive is typically 180 seconds
  const isClientOnline = (client: IngressPeer) => {
    if (client.last_handshake === 0) return false;
    const now = Date.now() / 1000; // Convert to seconds
    const timeSinceHandshake = now - client.last_handshake;
    return timeSinceHandshake < 180; // Consider online if handshake within last 3 minutes
  };

  const handleDelete = () => {
    if (deleteClient) {
      deletePeer(deleteClient.name, {
        onSuccess: () => setDeleteClient(null),
      });
    }
  };

  const handleUpdateOutbound = (outbound: string) => {
    if (editClient) {
      updatePeer(
        {
          name: editClient.name,
          updates: { default_outbound: outbound === "null" ? null : outbound },
        },
        {
          onSuccess: () => setEditClient(null),
        }
      );
    }
  };

  return (
    <>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("common.name")}</TableHead>
              <TableHead>{t("common.status")}</TableHead>
              <TableHead>{t("ingress.ipAddress")}</TableHead>
              <TableHead>{t("ingress.transfer")}</TableHead>
              <TableHead>{t("ingress.outbound")}</TableHead>
              <TableHead className="text-right">{t("common.actions")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {clients.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center h-24 text-muted-foreground">
                  {t("ingress.noClients")}
                </TableCell>
              </TableRow>
            ) : (
              clients.map((client) => {
                const isOnline = isClientOnline(client);
                return (
                  <TableRow key={client.public_key}>
                    <TableCell className="font-medium">{client.name}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div
                          className={`h-2 w-2 rounded-full ${
                            isOnline ? "bg-green-500 animate-pulse" : "bg-gray-300"
                          }`}
                        />
                        <span className="text-sm text-muted-foreground">
                          {isOnline ? t("common.online") : t("common.offline")}
                        </span>
                      </div>
                      {client.last_handshake > 0 && (
                        <div className="text-xs text-muted-foreground mt-1">
                          {t("ingress.lastSeen")}: {new Date(client.last_handshake * 1000).toLocaleString()}
                        </div>
                      )}
                    </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1">
                      {client.allowed_ips.map((ip) => (
                        <span key={ip} className="font-mono text-xs">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1 text-xs">
                      <div className="flex items-center gap-1">
                        <ArrowDown className="h-3 w-3 text-green-500" />
                        {formatBytes(client.rx_bytes)}
                      </div>
                      <div className="flex items-center gap-1">
                        <ArrowUp className="h-3 w-3 text-blue-500" />
                        {formatBytes(client.tx_bytes)}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      {client.default_outbound || t("ingress.globalDefault")}
                    </Badge>
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
                        <DropdownMenuItem onClick={() => setConfigClient(client)}>
                          <QrCode className="mr-2 h-4 w-4" />
                          {t("ingress.showConfig")}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => setEditClient(client)}>
                          <Settings className="mr-2 h-4 w-4" />
                          {t("ingress.settings")}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-destructive focus:text-destructive"
                          onClick={() => setDeleteClient(client)}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          {t("ingress.deleteClient")}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              );
              })
            )}
          </TableBody>
        </Table>
      </div>

      <ClientConfigDialog
        clientName={configClient?.name || null}
        open={!!configClient}
        onOpenChange={(open) => !open && setConfigClient(null)}
      />

      <AlertDialog open={!!deleteClient} onOpenChange={(open) => !open && setDeleteClient(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("common.confirm")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("ingress.deleteConfirm", {
                name: deleteClient?.name,
                defaultValue: `This will permanently delete the client ${deleteClient?.name}. This action cannot be undone.`
              })}
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

      <Dialog open={!!editClient} onOpenChange={(open) => !open && setEditClient(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("ingress.clientSettings")}: {editClient?.name}</DialogTitle>
            <DialogDescription>
              {t("ingress.clientSettingsDesc")}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label>{t("ingress.defaultOutbound")}</Label>
              <Select
                value={editClient?.default_outbound || "null"}
                onValueChange={handleUpdateOutbound}
                disabled={isUpdating}
              >
                <SelectTrigger>
                  <SelectValue placeholder={t("ingress.selectOutbound")} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="null">{t("ingress.globalDefault")}</SelectItem>
                  {outboundData?.available_outbounds.map((outbound) => (
                    <SelectItem key={outbound} value={outbound}>
                      {outbound}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditClient(null)}>
              {t("common.close")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
