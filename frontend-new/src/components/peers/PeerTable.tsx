import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu";
import { MoreHorizontal, Trash2, Power, PowerOff } from "lucide-react";
import type { PeerNode } from "@/types";
import { PeerInboundToggle } from "./PeerInboundToggle";
import { useConnectPeerNode, useDisconnectPeerNode, useDeletePeerNode } from "@/api/hooks/usePeerNodes";
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

interface PeerTableProps {
  peers: PeerNode[];
}

export function PeerTable({ peers }: PeerTableProps) {
  const connectPeer = useConnectPeerNode();
  const disconnectPeer = useDisconnectPeerNode();
  const deletePeer = useDeletePeerNode();

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "connected":
        return <Badge className="bg-green-500">Connected</Badge>;
      case "connecting":
        return <Badge className="bg-yellow-500">Connecting</Badge>;
      case "error":
        return <Badge variant="destructive">Error</Badge>;
      default:
        return <Badge variant="secondary">Disconnected</Badge>;
    }
  };

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Endpoint</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Inbound</TableHead>
            <TableHead className="w-[70px]"></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {peers.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="h-24 text-center">
                No peers found.
              </TableCell>
            </TableRow>
          ) : (
            peers.map((peer) => (
              <TableRow key={peer.tag}>
                <TableCell className="font-medium">
                  <div>{peer.name}</div>
                  <div className="text-xs text-muted-foreground">{peer.tag}</div>
                </TableCell>
                <TableCell>{peer.endpoint}</TableCell>
                <TableCell>
                  <Badge variant="outline">{peer.tunnel_type}</Badge>
                </TableCell>
                <TableCell>{getStatusBadge(peer.tunnel_status)}</TableCell>
                <TableCell>
                  <PeerInboundToggle peer={peer} />
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" className="h-8 w-8 p-0">
                        <span className="sr-only">Open menu</span>
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      {peer.tunnel_status === "connected" ? (
                        <DropdownMenuItem onClick={() => disconnectPeer.mutate(peer.tag)}>
                          <PowerOff className="mr-2 h-4 w-4" />
                          Disconnect
                        </DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem onClick={() => connectPeer.mutate(peer.tag)}>
                          <Power className="mr-2 h-4 w-4" />
                          Connect
                        </DropdownMenuItem>
                      )}
                      
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <DropdownMenuItem onSelect={(e) => e.preventDefault()} className="text-red-600">
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                          </DropdownMenuItem>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will permanently delete the peer node "{peer.name}".
                              This action cannot be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction 
                              onClick={() => deletePeer.mutate(peer.tag)}
                              className="bg-red-600 hover:bg-red-700"
                            >
                              Delete
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
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
