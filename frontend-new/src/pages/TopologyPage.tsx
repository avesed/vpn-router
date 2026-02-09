import { useTranslation } from "react-i18next";
import { useTopologyData } from "../api/hooks/useTopology";
import { TopologyCanvas } from "../components/topology/TopologyCanvas";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../components/ui/card";
import { Loader2 } from "lucide-react";

export default function TopologyPage() {
  const { t } = useTranslation();
  const { data, isLoading } = useTopologyData();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full p-8">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t("topology.title")}</h1>
        <p className="text-muted-foreground">{t("topology.subtitle")}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("topology.graphTitle")}</CardTitle>
          <CardDescription>{t("topology.graphDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <TopologyCanvas nodes={data.nodes} edges={data.edges} />
        </CardContent>
      </Card>
    </div>
  );
}
