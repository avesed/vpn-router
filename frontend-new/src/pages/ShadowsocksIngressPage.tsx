import { useShadowsocksIngressConfig } from "@/api/hooks/useShadowsocksIngress";
import { ShadowsocksIngressConfig } from "@/components/ss-ingress/ShadowsocksIngressConfig";
import { ShadowsocksIngressStats } from "@/components/ss-ingress/ShadowsocksIngressStats";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2 } from "lucide-react";

export default function ShadowsocksIngressPage() {
  const { isLoading } = useShadowsocksIngressConfig();

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
