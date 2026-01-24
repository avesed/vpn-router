import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useShadowsocksIngressStatus } from "@/api/hooks/useShadowsocksIngress";
import { Loader2, Activity, ArrowDownToLine, ArrowUpFromLine, Users, Wifi, WifiOff } from "lucide-react";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function ShadowsocksIngressStats() {
  const { data: status, isLoading, error } = useShadowsocksIngressStatus();

  if (isLoading) {
    return (
      <Card>
        <CardContent className="pt-6 flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="pt-6">
          <div className="text-center text-muted-foreground">
            <WifiOff className="h-8 w-8 mx-auto mb-2" />
            <p>Failed to load status</p>
            <p className="text-sm">{error instanceof Error ? error.message : "Unknown error"}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!status) {
    return (
      <Card>
        <CardContent className="pt-6">
          <div className="text-center text-muted-foreground">
            <WifiOff className="h-8 w-8 mx-auto mb-2" />
            <p>Shadowsocks ingress is not running</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Service Status
          </CardTitle>
          <CardDescription>Current Shadowsocks ingress server status</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                {status.enabled ? (
                  <Wifi className="h-4 w-4 text-green-500" />
                ) : (
                  <WifiOff className="h-4 w-4 text-muted-foreground" />
                )}
                <span className="text-sm text-muted-foreground">Status</span>
              </div>
              <p className="text-2xl font-bold">
                {status.enabled ? (
                  <span className="text-green-500">Running</span>
                ) : (
                  <span className="text-muted-foreground">Stopped</span>
                )}
              </p>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">Active Connections</span>
              </div>
              <p className="text-2xl font-bold">{status.active_connections}</p>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">Total Connections</span>
              </div>
              <p className="text-2xl font-bold">{status.total_connections}</p>
            </div>

            <div className="space-y-1">
              <span className="text-sm text-muted-foreground">Listen Address</span>
              <p className="text-lg font-mono">
                {status.listen_addr || "-"}:{status.listen_port || "-"}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Traffic Statistics</CardTitle>
          <CardDescription>Data transferred through Shadowsocks ingress</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <ArrowDownToLine className="h-4 w-4 text-blue-500" />
                <span className="text-sm text-muted-foreground">Bytes Received</span>
              </div>
              <p className="text-2xl font-bold">{formatBytes(status.bytes_received)}</p>
            </div>

            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <ArrowUpFromLine className="h-4 w-4 text-green-500" />
                <span className="text-sm text-muted-foreground">Bytes Sent</span>
              </div>
              <p className="text-2xl font-bold">{formatBytes(status.bytes_sent)}</p>
            </div>

            <div className="space-y-2">
              <span className="text-sm text-muted-foreground">Encryption Method</span>
              <p className="text-lg font-mono">{status.method || "-"}</p>
              <p className="text-xs text-muted-foreground">
                UDP: {status.udp_enabled ? "Enabled" : "Disabled"}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
