import { useState } from "react";
import { useV2RayIngressConfig } from "@/api/hooks/useV2RayIngress";
import { V2RayIngressConfig } from "@/components/v2ray-ingress/V2RayIngressConfig";
import { V2RayUserTable } from "@/components/v2ray-ingress/V2RayUserTable";
import { AddV2RayUserDialog } from "@/components/v2ray-ingress/AddV2RayUserDialog";
import { VlessBridgeStats } from "@/components/v2ray-ingress/VlessBridgeStats";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Plus, Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function V2RayIngressPage() {
  const { data: ingressData, isLoading } = useV2RayIngressConfig();
  const [isAddUserOpen, setIsAddUserOpen] = useState(false);

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
          <h1 className="text-3xl font-bold tracking-tight">V2Ray Ingress</h1>
          <p className="text-muted-foreground">
            Manage V2Ray/Xray server and users for incoming connections.
          </p>
        </div>
        <Button onClick={() => setIsAddUserOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Add User
        </Button>
      </div>

      <Tabs defaultValue="users" className="space-y-4">
        <TabsList>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="config">Server Configuration</TabsTrigger>
          <TabsTrigger value="stats">Bridge Status</TabsTrigger>
        </TabsList>

        <TabsContent value="users" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>V2Ray Users</CardTitle>
              <CardDescription>
                Manage users allowed to connect to this router via V2Ray/Xray.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <V2RayUserTable users={ingressData?.users || []} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="config">
          <V2RayIngressConfig />
        </TabsContent>

        <TabsContent value="stats">
          <VlessBridgeStats />
        </TabsContent>
      </Tabs>

      <AddV2RayUserDialog open={isAddUserOpen} onOpenChange={setIsAddUserOpen} />
    </div>
  );
}
