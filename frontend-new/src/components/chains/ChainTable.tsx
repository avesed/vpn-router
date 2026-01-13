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
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import { MoreHorizontal, Play, Square, Trash2, Activity } from "lucide-react";
import type { NodeChain } from "../../types";
import { ChainHealthStatus } from "./ChainHealthStatus";
import { useActivateChain, useDeactivateChain, useDeleteNodeChain, useChainHealthCheck } from "../../api/hooks/useChains";
import { toast } from "sonner";
import { Badge } from "../ui/badge";

interface ChainTableProps {
  chains: NodeChain[];
}

export function ChainTable({ chains }: ChainTableProps) {
  const activateChain = useActivateChain();
  const deactivateChain = useDeactivateChain();
  const deleteChain = useDeleteNodeChain();
  const healthCheck = useChainHealthCheck();

  const handleActivate = (tag: string) => {
    toast.promise(activateChain.mutateAsync(tag), {
      loading: "Activating chain...",
      success: "Chain activated",
      error: "Failed to activate chain",
    });
  };

  const handleDeactivate = (tag: string) => {
    toast.promise(deactivateChain.mutateAsync(tag), {
      loading: "Deactivating chain...",
      success: "Chain deactivated",
      error: "Failed to deactivate chain",
    });
  };

  const handleDelete = (tag: string) => {
    if (!confirm(`Are you sure you want to delete chain ${tag}?`)) return;
    toast.promise(deleteChain.mutateAsync(tag), {
      loading: "Deleting chain...",
      success: "Chain deleted",
      error: "Failed to delete chain",
    });
  };

  const handleHealthCheck = (tag: string) => {
    toast.promise(healthCheck.mutateAsync(tag), {
      loading: "Running health check...",
      success: "Health check completed",
      error: "Health check failed",
    });
  };

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Hops</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>State</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {chains.length === 0 ? (
            <TableRow>
              <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                No chains configured.
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
                    {chain.chain_state || "inactive"}
                  </Badge>
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
                      {chain.chain_state === "active" ? (
                        <DropdownMenuItem onClick={() => handleDeactivate(chain.tag)}>
                          <Square className="mr-2 h-4 w-4" /> Deactivate
                        </DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem onClick={() => handleActivate(chain.tag)}>
                          <Play className="mr-2 h-4 w-4" /> Activate
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem onClick={() => handleHealthCheck(chain.tag)}>
                        <Activity className="mr-2 h-4 w-4" /> Health Check
                      </DropdownMenuItem>
                      <DropdownMenuItem className="text-destructive" onClick={() => handleDelete(chain.tag)}>
                        <Trash2 className="mr-2 h-4 w-4" /> Delete
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
  );
}
