import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { EgressItem, EgressTrafficInfo } from "../../types";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { useTestEgress } from "../../api/hooks/useEgress";
import { toast } from "sonner";
import { Activity, Trash2, Edit, Play, Globe, Server, Shield, Network, ArrowUpDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface EgressCardProps {
  egress: EgressItem;
  onDelete?: (tag: string) => void;
  onEdit?: (egress: EgressItem) => void;
  showActions?: boolean;
  trafficInfo?: EgressTrafficInfo;
}

// Format bytes to human readable string
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

export function EgressCard({ egress, onDelete, onEdit, showActions = true, trafficInfo }: EgressCardProps) {
  const { t } = useTranslation();
  const [testResult, setTestResult] = useState<{ success: boolean; delay: number; message: string } | null>(null);
  const testEgress = useTestEgress();

  const handleTest = () => {
    setTestResult(null);
    toast.promise(
      testEgress.mutateAsync({ tag: egress.tag }),
      {
        loading: t("egress.testing"),
        success: (data) => {
          setTestResult(data);
          return `${t("egress.testComplete")}: ${data.message}`;
        },
        error: (err) => `${t("egress.testFailed")}: ${err.message}`,
      }
    );
  };

  const getIcon = () => {
    switch (egress.type) {
      case "pia": return <Shield className="h-5 w-5 text-green-500" />;
      case "custom": return <Server className="h-5 w-5 text-blue-500" />;
      case "direct": return <Network className="h-5 w-5 text-gray-500" />;
      case "warp": return <Globe className="h-5 w-5 text-orange-500" />;
      case "v2ray": return <Activity className="h-5 w-5 text-purple-500" />;
      default: return <Globe className="h-5 w-5" />;
    }
  };

  const getStatusColor = (delay?: number) => {
    if (delay === undefined) return "bg-gray-100 text-gray-800";
    if (delay < 0) return "bg-red-100 text-red-800";
    if (delay < 100) return "bg-green-100 text-green-800";
    if (delay < 300) return "bg-yellow-100 text-yellow-800";
    return "bg-orange-100 text-orange-800";
  };

  // Calculate total traffic
  const totalTraffic = trafficInfo ? trafficInfo.tx_bytes + trafficInfo.rx_bytes : 0;

  return (
    <Card className="w-full">
      <CardHeader className="pb-2">
        <div className="flex justify-between items-start">
          <div className="flex items-center gap-2">
            {getIcon()}
            <div>
              <CardTitle className="text-lg">{egress.tag}</CardTitle>
              <CardDescription className="text-xs mt-1">{egress.description || t("egress.noDescription")}</CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {trafficInfo && trafficInfo.active && (
              <Badge variant="outline" className="text-xs text-emerald-600 border-emerald-600">
                <ArrowUpDown className="h-3 w-3 mr-1" />
                {formatBytes(totalTraffic)}
              </Badge>
            )}
            <Badge variant={egress.is_configured ? "default" : "secondary"}>
              {egress.type.toUpperCase()}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pb-2 text-sm">
        <div className="grid grid-cols-2 gap-2">
          {egress.server && (
            <div className="flex flex-col">
              <span className="text-xs text-muted-foreground">{t("egress.server")}</span>
              <span className="font-medium truncate" title={egress.server}>{egress.server}</span>
            </div>
          )}
          {egress.port && (
            <div className="flex flex-col">
              <span className="text-xs text-muted-foreground">{t("common.port")}</span>
              <span className="font-medium">{egress.port}</span>
            </div>
          )}
          {egress.bind_interface && (
            <div className="flex flex-col">
              <span className="text-xs text-muted-foreground">{t("egress.interface")}</span>
              <span className="font-medium">{egress.bind_interface}</span>
            </div>
          )}
          {/* Traffic details for WireGuard tunnels */}
          {trafficInfo && trafficInfo.active && (
            <div className="col-span-2 mt-2 flex items-center gap-4 text-xs text-muted-foreground">
              <span>↑ {formatBytes(trafficInfo.tx_bytes)}</span>
              <span>↓ {formatBytes(trafficInfo.rx_bytes)}</span>
              {trafficInfo.endpoint && (
                <span className="truncate" title={trafficInfo.endpoint}>{trafficInfo.endpoint}</span>
              )}
            </div>
          )}
          {testResult && (
            <div className="col-span-2 mt-2">
              <div className={cn("text-xs px-2 py-1 rounded flex items-center gap-2", getStatusColor(testResult.success ? testResult.delay : -1))}>
                <Activity className="h-3 w-3" />
                {testResult.success ? `${testResult.delay}ms` : t("common.failed")}
              </div>
            </div>
          )}
        </div>
      </CardContent>
      {showActions && (
        <CardFooter className="pt-2 flex justify-end gap-2">
          <Button variant="ghost" size="icon" onClick={handleTest} disabled={testEgress.isPending}>
            <Play className="h-4 w-4" />
          </Button>
          {onEdit && (
            <Button variant="ghost" size="icon" onClick={() => onEdit(egress)}>
              <Edit className="h-4 w-4" />
            </Button>
          )}
          {onDelete && (
            <Button variant="ghost" size="icon" className="text-destructive hover:text-destructive" onClick={() => onDelete(egress.tag)}>
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </CardFooter>
      )}
    </Card>
  );
}
