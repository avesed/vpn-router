import { useVlessBridgeStatus } from "@/api/hooks/useV2RayIngress";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Activity, ArrowUpRight, ArrowDownRight, AlertTriangle, Wifi, WifiOff, Network } from "lucide-react";

export function VlessBridgeStats() {
  const { data: status, isLoading, error } = useVlessBridgeStatus();

  if (isLoading) {
    return (
      <Card>
        <CardContent className="pt-6 flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    );
  }

  if (error || !status?.available) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <WifiOff className="h-5 w-5 text-muted-foreground" />
            VLESS-WG Bridge
          </CardTitle>
          <CardDescription>
            Bridge statistics unavailable
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-muted-foreground">
            <AlertTriangle className="h-4 w-4" />
            <span>{status?.message || "rust-router not available"}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  const bridgeStats = status.bridge_stats;

  return (
    <div className="space-y-6">
      {/* Connection Status Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            VLESS Inbound Status
          </CardTitle>
          <CardDescription>
            Native Rust VLESS server status (rust-router)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="space-y-1">
              <div className="text-sm text-muted-foreground">Status</div>
              <div className="flex items-center gap-2">
                {status.running ? (
                  <>
                    <Wifi className="h-4 w-4 text-green-500" />
                    <Badge variant="default" className="bg-green-500">Running</Badge>
                  </>
                ) : (
                  <>
                    <WifiOff className="h-4 w-4 text-gray-400" />
                    <Badge variant="secondary">Stopped</Badge>
                  </>
                )}
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-sm text-muted-foreground">Listen Address</div>
              <div className="font-mono text-sm">{status.listen_address || "N/A"}</div>
            </div>

            <div className="space-y-1">
              <div className="text-sm text-muted-foreground">TLS</div>
              <div>
                {status.tls_enabled ? (
                  <Badge variant="default" className="bg-blue-500">Enabled</Badge>
                ) : (
                  <Badge variant="secondary">Disabled</Badge>
                )}
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-sm text-muted-foreground">UDP</div>
              <div>
                {status.udp_enabled !== false ? (
                  <Badge variant="default" className="bg-purple-500">Enabled</Badge>
                ) : (
                  <Badge variant="secondary">Disabled</Badge>
                )}
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-sm text-muted-foreground">Users</div>
              <div className="text-2xl font-bold">{status.user_count || 0}</div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t">
            <div className="space-y-1">
              <div className="text-sm text-muted-foreground flex items-center gap-1">
                <Activity className="h-4 w-4" />
                Active Connections
              </div>
              <div className="text-2xl font-bold text-green-600">
                {status.active_connections?.toLocaleString() || 0}
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-sm text-muted-foreground">Total Connections</div>
              <div className="text-2xl font-bold">
                {status.total_connections?.toLocaleString() || 0}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Bridge Stats Card (only show if bridge stats available) */}
      {bridgeStats && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ArrowUpRight className="h-5 w-5" />
              VLESS → WireGuard Bridge
            </CardTitle>
            <CardDescription>
              Statistics for VLESS connections routed through WireGuard tunnels
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="space-y-1">
                <div className="text-sm text-muted-foreground">Active Sessions</div>
                <div className="text-2xl font-bold text-green-600">
                  {bridgeStats.active_sessions.toLocaleString()}
                </div>
              </div>

              <div className="space-y-1">
                <div className="text-sm text-muted-foreground">Sessions Registered</div>
                <div className="text-2xl font-bold">
                  {bridgeStats.sessions_registered.toLocaleString()}
                </div>
              </div>

              <div className="space-y-1">
                <div className="text-sm text-muted-foreground">Sessions Closed</div>
                <div className="text-2xl font-bold">
                  {bridgeStats.sessions_unregistered.toLocaleString()}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t">
              <div className="space-y-1">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <ArrowDownRight className="h-4 w-4 text-green-500" />
                  Packets Routed
                </div>
                <div className="text-2xl font-bold text-green-600">
                  {bridgeStats.packets_routed.toLocaleString()}
                </div>
              </div>

              <div className="space-y-1">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  Packets Dropped
                </div>
                <div className="text-2xl font-bold text-yellow-600">
                  {bridgeStats.packets_dropped.toLocaleString()}
                </div>
              </div>

              <div className="space-y-1">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  Channel Full
                </div>
                <div className="text-2xl font-bold text-red-600">
                  {bridgeStats.channel_full.toLocaleString()}
                </div>
              </div>
            </div>

            {/* Success Rate */}
            {(bridgeStats.packets_routed + bridgeStats.packets_dropped) > 0 && (
              <div className="mt-4 pt-4 border-t">
                <div className="text-sm text-muted-foreground mb-2">Routing Success Rate</div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-gray-200 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-green-500"
                      style={{
                        width: `${(bridgeStats.packets_routed / (bridgeStats.packets_routed + bridgeStats.packets_dropped) * 100).toFixed(1)}%`
                      }}
                    />
                  </div>
                  <span className="text-sm font-medium">
                    {(bridgeStats.packets_routed / (bridgeStats.packets_routed + bridgeStats.packets_dropped) * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* No Bridge Stats Info */}
      {!bridgeStats && status.running && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-muted-foreground">
              <ArrowUpRight className="h-5 w-5" />
              VLESS → WireGuard Bridge
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">
              No WireGuard bridge sessions active. Bridge statistics will appear when VLESS connections are routed through WireGuard outbounds.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
