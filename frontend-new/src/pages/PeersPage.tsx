import { useTranslation } from "react-i18next";
import { usePeerNodes } from "@/api/hooks/usePeerNodes";
import { PeerTable } from "@/components/peers/PeerTable";
import { GeneratePairingDialog } from "@/components/peers/GeneratePairingDialog";
import { ImportPairingDialog } from "@/components/peers/ImportPairingDialog";
import { CompletePairingDialog } from "@/components/peers/CompletePairingDialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function PeersPage() {
  const { t } = useTranslation();
  const { data: peersData, isLoading } = usePeerNodes();

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("peers.title")}</h1>
          <p className="text-muted-foreground">{t("peers.subtitle")}</p>
        </div>
        <div className="flex gap-2">
          <ImportPairingDialog />
          <CompletePairingDialog />
          <GeneratePairingDialog />
        </div>
      </div>

        <Card>
          <CardHeader>
            <CardTitle>{t("peers.listTitle")}</CardTitle>
            <CardDescription>{t("peers.listDescription")}</CardDescription>
          </CardHeader>

        <CardContent>
          {isLoading ? (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                {t("common.loading")}
              </div>

          ) : (
            <PeerTable peers={peersData?.nodes || []} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
