import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { Button } from "../ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import { MoreHorizontal, Play, Square, Trash2, Activity, Edit } from "lucide-react";
import type { NodeChain } from "../../types";
import { ChainHealthStatus } from "./ChainHealthStatus";
import { ChainEditDialog } from "./ChainEditDialog";
import { useActivateChain, useDeactivateChain, useDeleteNodeChain, useChainHealthCheck } from "../../api/hooks/useChains";
import { toast } from "sonner";
import { Badge } from "../ui/badge";

interface ChainTableProps {
  chains: NodeChain[];
}

export function ChainTable({ chains }: ChainTableProps) {
  const { t } = useTranslation();
  const [editingChain, setEditingChain] = useState<NodeChain | null>(null);
  const activateChain = useActivateChain();
  const deactivateChain = useDeactivateChain();
  const deleteChain = useDeleteNodeChain();
  const healthCheck = useChainHealthCheck();

  const handleActivate = (tag: string) => {
    toast.promise(activateChain.mutateAsync(tag), {
      loading: t("chains.activating"),
      success: t("chains.activateSuccess", { name: tag }),
      error: t("chains.activateFailed"),
    });
  };

  const handleDeactivate = (tag: string) => {
    toast.promise(deactivateChain.mutateAsync(tag), {
      loading: t("chains.deactivating"),
      success: t("chains.deactivateSuccess", { name: tag }),
      error: t("chains.deactivateFailed"),
    });
  };

  const handleDelete = (tag: string) => {
    if (!confirm(t("chains.confirmDelete", { name: tag }))) return;
    toast.promise(deleteChain.mutateAsync(tag), {
      loading: t("common.deleting"),
      success: t("chains.deleteSuccess", { name: tag }),
      error: t("chains.deleteFailed"),
    });
  };

  const handleHealthCheck = (tag: string) => {
    toast.promise(healthCheck.mutateAsync(tag), {
      loading: t("chains.checking"),
      success: t("chains.healthCheckSuccess"),
      error: t("chains.healthCheckFailed"),
    });
  };

  const getStateLabel = (state?: string) => {
    switch (state) {
      case "active":
        return t("chains.state.active");
      case "activating":
        return t("chains.state.activating");
      case "error":
        return t("chains.state.error");
      case "inactive":
      default:
        return t("chains.state.inactive");
    }
  };

  return (
    <>
    <div className="rounded-md border">
      <Table>
        <TableHeader>
            <TableRow>
              <TableHead>{t("chains.name")}</TableHead>
              <TableHead>{t("chains.hops")}</TableHead>
              <TableHead>{t("chains.healthStatus")}</TableHead>
              <TableHead>{t("chains.stateLabel")}</TableHead>
              <TableHead className="text-right">{t("common.actions")}</TableHead>
            </TableRow>

        </TableHeader>
        <TableBody>
          {chains.length === 0 ? (
            <TableRow>
              <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                {t("chains.noChains")}
              </TableCell>
            </TableRow>
          ) : (
            chains.map((chain) => (
              <TableRow key={chain.tag}>
                <TableCell>
                  <div className="font-medium">{chain.name}</div>
                  <div className="text-xs text-muted-foreground">{chain.description}</div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {chain.hops.map((hop, index) => (
                      <div key={index} className="flex items-center">
                        <Badge variant="secondary" className="text-xs">
                          {hop}
                        </Badge>
                        {index < chain.hops.length - 1 && (
                          <span className="mx-1 text-muted-foreground">→</span>
                        )}
                      </div>
                    ))}
                    {chain.exit_egress && (
                      <div className="flex items-center">
                        <span className="mx-1 text-muted-foreground">→</span>
                        <Badge variant="outline" className="text-xs border-dashed">
                          {chain.exit_egress}
                        </Badge>
                      </div>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <ChainHealthStatus status={chain.health_status} />
                </TableCell>
                <TableCell>
                  <Badge variant={chain.chain_state === "active" ? "default" : "secondary"}>
                    {getStateLabel(chain.chain_state)}
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
                      {chain.chain_state === "active" ? (
                        <DropdownMenuItem onClick={() => handleDeactivate(chain.tag)}>
                          <Square className="mr-2 h-4 w-4" /> {t("chains.deactivate")}
                        </DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem onClick={() => handleActivate(chain.tag)}>
                          <Play className="mr-2 h-4 w-4" /> {t("chains.activate")}
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem onClick={() => handleHealthCheck(chain.tag)}>
                        <Activity className="mr-2 h-4 w-4" /> {t("chains.checkHealth")}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => setEditingChain(chain)}>
                        <Edit className="mr-2 h-4 w-4" /> {t("common.edit")}
                      </DropdownMenuItem>
                      <DropdownMenuItem className="text-destructive" onClick={() => handleDelete(chain.tag)}>
                        <Trash2 className="mr-2 h-4 w-4" /> {t("common.delete")}
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
    
    <ChainEditDialog
      open={!!editingChain}
      onOpenChange={(open) => !open && setEditingChain(null)}
      chain={editingChain}
    />
    </>
  );
}
