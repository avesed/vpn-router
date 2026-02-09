import { useShadowsocksIngressConfig } from "@/api/hooks/useShadowsocksIngress";
import { useAuth } from "@/providers/AuthProvider";
import { ShadowsocksIngressConfig } from "@/components/ss-ingress/ShadowsocksIngressConfig";
import { ShadowsocksIngressStats } from "@/components/ss-ingress/ShadowsocksIngressStats";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2, ShieldAlert } from "lucide-react";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function ShadowsocksIngressPage() {
  const { isAdmin } = useAuth();
  const { isLoading } = useShadowsocksIngressConfig();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  // This page is admin-only
  if (!isAdmin) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Shadowsocks Ingress</h1>
          <p className="text-muted-foreground">
            Manage Shadowsocks server for incoming connections.
          </p>
        </div>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              Admin Only
            </CardTitle>
            <CardDescription>
              Shadowsocks server configuration is restricted to administrators.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Shadowsocks Ingress</h1>
          <p className="text-muted-foreground">
            Manage Shadowsocks server for incoming connections.
          </p>
        </div>
      </div>

      <Tabs defaultValue="config" className="space-y-4">
        <TabsList>
          <TabsTrigger value="config">Server Configuration</TabsTrigger>
          <TabsTrigger value="stats">Status</TabsTrigger>
        </TabsList>

        <TabsContent value="config">
          <ShadowsocksIngressConfig />
        </TabsContent>

        <TabsContent value="stats">
          <ShadowsocksIngressStats />
        </TabsContent>
      </Tabs>
    </div>
  );
}
