import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Activity,
  Trash2,
  Settings,
  RefreshCw,
  Scale,
  ArrowRightLeft,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Loader2
} from "lucide-react";
import type { OutboundGroup, MemberHealthStatus } from "../../types";
import { ECMP_ALGORITHMS } from "../../types";

interface GroupCardProps {
  group: OutboundGroup;
  onEdit?: (group: OutboundGroup) => void;
  onDelete?: (tag: string) => void;
  onHealthCheck?: (tag: string) => void;
  isCheckingHealth?: boolean;
}

export function GroupCard({
  group,
  onEdit,
  onDelete,
  onHealthCheck,
  isCheckingHealth
}: GroupCardProps) {
  const { t } = useTranslation();

  const isLoadBalance = group.type === "loadbalance";
  const healthyCount = group.health_status
    ? Object.values(group.health_status).filter(s => s.healthy).length
    : 0;
  const totalMembers = group.members?.length || 0;

  const getHealthIcon = (status?: MemberHealthStatus) => {
    if (!status) return <HelpCircle className="h-3 w-3 text-muted-foreground" />;
    return status.healthy
      ? <CheckCircle2 className="h-3 w-3 text-emerald-500" />
      : <XCircle className="h-3 w-3 text-red-500" />;
  };

  const getHealthBadgeVariant = () => {
    if (!group.health_status || Object.keys(group.health_status).length === 0) {
      return "secondary";
    }
    if (healthyCount === totalMembers) return "default";
    if (healthyCount > 0) return "secondary";
    return "destructive";
  };

  return (
    <Card className="relative overflow-hidden">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              {isLoadBalance ? (
                <Scale className="h-4 w-4 text-blue-500 shrink-0" />
              ) : (
                <ArrowRightLeft className="h-4 w-4 text-amber-500 shrink-0" />
              )}
              <CardTitle className="text-base truncate">{group.tag}</CardTitle>
            </div>
            <p className="text-sm text-muted-foreground mt-1 truncate">
              {group.description || t("groups.noDescription")}
            </p>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <Badge variant={isLoadBalance ? "default" : "secondary"}>
              {isLoadBalance ? t("groups.loadbalance") : t("groups.failover")}
            </Badge>
            {!group.enabled && (
              <Badge variant="outline" className="text-muted-foreground">
                {t("common.disabled")}
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {/* Health Status Summary */}
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">{t("groups.members")}</span>
          <Badge variant={getHealthBadgeVariant()}>
            <Activity className="h-3 w-3 mr-1" />
            {healthyCount}/{totalMembers} {t("groups.healthy").toLowerCase()}
          </Badge>
        </div>

        {/* Members List */}
        <div className="space-y-1.5">
          {group.members?.slice(0, 5).map((member) => {
            const status = group.health_status?.[member];
            const weight = group.weights?.[member];

            return (
              <div
                key={member}
                className="flex items-center justify-between text-sm py-1 px-2 rounded bg-muted/50"
              >
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  {getHealthIcon(status)}
                  <span className="truncate">{member}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {isLoadBalance && weight !== undefined && (
                    <span className="text-xs text-muted-foreground">
                      w:{weight}
                    </span>
                  )}
                  {status && (
                    <span className={`text-xs ${status.healthy ? 'text-emerald-500' : 'text-red-500'}`}>
                      {status.latency_ms > 0 ? `${status.latency_ms}ms` : '-'}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
          {totalMembers > 5 && (
            <p className="text-xs text-muted-foreground text-center py-1">
              +{totalMembers - 5} more
            </p>
          )}
        </div>

        {/* Algorithm (only for loadbalance) */}
        {isLoadBalance && group.algorithm && (
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{t("groups.algorithm")}</span>
            <span className="text-xs">
              {ECMP_ALGORITHMS.find(a => a.value === group.algorithm)?.label || group.algorithm}
            </span>
          </div>
        )}

        {/* Routing Table */}
        {group.routing_table && (
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{t("groups.routingTable")}</span>
            <span className="font-mono">{group.routing_table}</span>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 pt-2 border-t">
          <Button
            variant="outline"
            size="sm"
            className="flex-1"
            onClick={() => onHealthCheck?.(group.tag)}
            disabled={isCheckingHealth}
          >
            {isCheckingHealth ? (
              <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            ) : (
              <RefreshCw className="h-3 w-3 mr-1" />
            )}
            {t("groups.checkHealth")}
          </Button>
          {onEdit && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => onEdit(group)}
            >
              <Settings className="h-4 w-4" />
            </Button>
          )}
          {onDelete && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => onDelete(group.tag)}
            >
              <Trash2 className="h-4 w-4 text-destructive" />
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
