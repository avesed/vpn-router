import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNodeChains } from "../api/hooks/useChains";
import { ChainTable } from "../components/chains/ChainTable";
import { ChainCreateDialog } from "../components/chains/ChainCreateDialog";
import { Button } from "../components/ui/button";
import { Plus } from "lucide-react";

export default function ChainsPage() {
  const { t } = useTranslation();
  const { data: chainsData, isLoading, error } = useNodeChains();
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  if (isLoading) return <div>{t("common.loading")}</div>;
  if (error) return <div>{t("common.error")}: {error.message}</div>;

  const chains = chainsData?.chains || [];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("chains.title")}</h1>
          <p className="text-muted-foreground">{t("chains.subtitle")}</p>
        </div>
        <Button onClick={() => setShowCreateDialog(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t("chains.addChain")}
        </Button>
      </div>

      <ChainTable chains={chains} />
      <ChainCreateDialog open={showCreateDialog} onOpenChange={setShowCreateDialog} />
    </div>
  );
}
