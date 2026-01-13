import { useState } from "react";
import type { EgressItem } from "../../types";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { useTestEgress } from "../../api/hooks/useEgress";
import { toast } from "sonner";
import { Activity, Trash2, Edit, Play, Globe, Server, Shield, Network } from "lucide-react";
import { cn } from "@/lib/utils";

interface EgressCardProps {
  egress: EgressItem;
  onDelete?: (tag: string) => void;
  onEdit?: (egress: EgressItem) => void;
  showActions?: boolean;
}

export function EgressCard({ egress, onDelete, onEdit, showActions = true }: EgressCardProps) {
  const [testResult, setTestResult] = useState<{ success: boolean; delay: number; message: string } | null>(null);
  const testEgress = useTestEgress();

  const handleTest = () => {
    setTestResult(null);
    toast.promise(
      testEgress.mutateAsync({ tag: egress.tag }),
      {
        loading: "Testing connection...",
        success: (data) => {
          setTestResult(data);
          return `Test complete: ${data.message}`;
        },
        error: (err) => `Test failed: ${err.message}`,
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

  return (
    <Card className="w-full">
      <CardHeader className="pb-2">
        <div className="flex justify-between items-start">
          <div className="flex items-center gap-2">
            {getIcon()}
            <div>
              <CardTitle className="text-lg">{egress.tag}</CardTitle>
              <CardDescription className="text-xs mt-1">{egress.description || "No description"}</CardDescription>
            </div>
          </div>
          <Badge variant={egress.is_configured ? "default" : "secondary"}>
            {egress.type.toUpperCase()}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="pb-2 text-sm">
        <div className="grid grid-cols-2 gap-2">
          {egress.server && (
            <div className="flex flex-col">
              <span className="text-xs text-muted-foreground">Server</span>
              <span className="font-medium truncate" title={egress.server}>{egress.server}</span>
            </div>
          )}
          {egress.port && (
            <div className="flex flex-col">
              <span className="text-xs text-muted-foreground">Port</span>
              <span className="font-medium">{egress.port}</span>
            </div>
          )}
          {egress.bind_interface && (
            <div className="flex flex-col">
              <span className="text-xs text-muted-foreground">Interface</span>
              <span className="font-medium">{egress.bind_interface}</span>
            </div>
          )}
          {testResult && (
            <div className="col-span-2 mt-2">
              <div className={cn("text-xs px-2 py-1 rounded flex items-center gap-2", getStatusColor(testResult.success ? testResult.delay : -1))}>
                <Activity className="h-3 w-3" />
                {testResult.success ? `${testResult.delay}ms` : "Failed"}
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
