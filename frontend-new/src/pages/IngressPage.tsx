import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useIngressConfig } from "@/api/hooks/useIngress";
import { IngressSettings } from "@/components/ingress/IngressSettings";
import { ClientTable } from "@/components/ingress/ClientTable";
import { AddClientDialog } from "@/components/ingress/AddClientDialog";
import { ClientConfigDialog } from "@/components/ingress/ClientConfigDialog";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Plus, Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function IngressPage() {
  const { t } = useTranslation();
  const { data: ingressData, isLoading } = useIngressConfig();
  const [isAddClientOpen, setIsAddClientOpen] = useState(false);
  const [configClientName, setConfigClientName] = useState<string | null>(null);
  const [configClientPrivateKey, setConfigClientPrivateKey] = useState<string | undefined>(undefined);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("nav.ingressClient")}</h1>
          <p className="text-muted-foreground">
            {t("ingress.subtitle")}
          </p>
        </div>
        <Button onClick={() => setIsAddClientOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          {t("ingress.addClient")}
        </Button>
      </div>

      <Tabs defaultValue="clients" className="space-y-4">
        <TabsList>
          <TabsTrigger value="clients">{t("common.clients", "Clients")}</TabsTrigger>
          <TabsTrigger value="settings">{t("ingress.serverSettings")}</TabsTrigger>
        </TabsList>

        <TabsContent value="clients" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>{t("ingress.connectedClients")}</CardTitle>
              <CardDescription>
                {t("ingress.subtitle")}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ClientTable clients={ingressData?.peers || []} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings">
          <IngressSettings />
        </TabsContent>
      </Tabs>

      <AddClientDialog 
        open={isAddClientOpen} 
        onOpenChange={setIsAddClientOpen} 
        onClientCreated={(name, privateKey) => {
          setConfigClientName(name);
          setConfigClientPrivateKey(privateKey);
        }}
      />

      <ClientConfigDialog
        clientName={configClientName}
        privateKey={configClientPrivateKey}
        open={!!configClientName}
        onOpenChange={(open) => {
          if (!open) {
            setConfigClientName(null);
            setConfigClientPrivateKey(undefined);
          }
        }}
      />
    </div>
  );
}
