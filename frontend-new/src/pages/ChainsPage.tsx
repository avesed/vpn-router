import { useState } from "react";
import { useNodeChains } from "../api/hooks/useChains";
import { ChainTable } from "../components/chains/ChainTable";
import { ChainCreateDialog } from "../components/chains/ChainCreateDialog";
import { Button } from "../components/ui/button";
import { Plus } from "lucide-react";

export default function ChainsPage() {
  const { data: chainsData, isLoading, error } = useNodeChains();
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  if (isLoading) return <div>Loading chains...</div>;
  if (error) return <div>Error loading chains: {error.message}</div>;

  const chains = chainsData?.chains || [];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Node Chains</h1>
          <p className="text-muted-foreground">
            Manage multi-hop chains for advanced routing privacy.
          </p>
        </div>
        <Button onClick={() => setShowCreateDialog(true)}>
          <Plus className="mr-2 h-4 w-4" /> Create Chain
        </Button>
      </div>

      <ChainTable chains={chains} />
      <ChainCreateDialog open={showCreateDialog} onOpenChange={setShowCreateDialog} />
    </div>
  );
}
