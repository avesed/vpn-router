import { useState } from "react";
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
          <h1 className="text-3xl font-bold tracking-tight">WireGuard Ingress</h1>
          <p className="text-muted-foreground">
            Manage WireGuard server and clients for incoming connections.
          </p>
        </div>
        <Button onClick={() => setIsAddClientOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Add Client
        </Button>
      </div>

      <Tabs defaultValue="clients" className="space-y-4">
        <TabsList>
          <TabsTrigger value="clients">Clients</TabsTrigger>
          <TabsTrigger value="settings">Server Settings</TabsTrigger>
        </TabsList>
        
        <TabsContent value="clients" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Connected Clients</CardTitle>
              <CardDescription>
                Manage devices allowed to connect to this router via WireGuard.
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
