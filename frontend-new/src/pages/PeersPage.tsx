import { usePeerNodes } from "@/api/hooks/usePeerNodes";
import { PeerTable } from "@/components/peers/PeerTable";
import { GeneratePairingDialog } from "@/components/peers/GeneratePairingDialog";
import { ImportPairingDialog } from "@/components/peers/ImportPairingDialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function PeersPage() {
  const { data: peersData, isLoading } = usePeerNodes();

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Peer Nodes</h1>
          <p className="text-muted-foreground">
            Manage peer-to-peer connections with other gateways.
          </p>
        </div>
        <div className="flex gap-2">
          <ImportPairingDialog />
          <GeneratePairingDialog />
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Connected Peers</CardTitle>
          <CardDescription>
            List of configured peer nodes and their connection status.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              Loading peers...
            </div>
          ) : (
            <PeerTable peers={peersData?.nodes || []} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
