import { useTranslation } from "react-i18next";
import type { ChainHealthStatus as HealthStatusType } from "../../types";
import { Badge } from "../ui/badge";
import { CheckCircle2, AlertTriangle, XCircle, HelpCircle } from "lucide-react";

interface ChainHealthStatusProps {
  status: HealthStatusType;
}

export function ChainHealthStatus({ status }: ChainHealthStatusProps) {
  const { t } = useTranslation();

  switch (status) {
    case "healthy":
      return (
        <Badge variant="outline" className="bg-green-100 text-green-800 border-green-200 flex gap-1 items-center">
          <CheckCircle2 className="h-3 w-3" /> {t("chains.status.healthy")}
        </Badge>
      );
    case "degraded":
      return (
        <Badge variant="outline" className="bg-yellow-100 text-yellow-800 border-yellow-200 flex gap-1 items-center">
          <AlertTriangle className="h-3 w-3" /> {t("chains.status.degraded")}
        </Badge>
      );
    case "unhealthy":
      return (
        <Badge variant="outline" className="bg-red-100 text-red-800 border-red-200 flex gap-1 items-center">
          <XCircle className="h-3 w-3" /> {t("chains.status.unhealthy")}
        </Badge>
      );
    default:
      return (
        <Badge variant="outline" className="bg-gray-100 text-gray-800 border-gray-200 flex gap-1 items-center">
          <HelpCircle className="h-3 w-3" /> {t("chains.status.unknown")}
        </Badge>
      );
  }
}
