import { useTranslation } from "react-i18next";
import { Checkbox } from "../ui/checkbox";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { Eye } from "lucide-react";
import type { DomainListSummary } from "../../types";

interface ListItemRowProps {
  list: DomainListSummary;
  isSelected: boolean;
  onToggle: () => void;
  onViewDomains: () => void;
}

export function ListItemRow({
  list,
  isSelected,
  onToggle,
  onViewDomains,
}: ListItemRowProps) {
  const { t } = useTranslation();

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onToggle}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onToggle();
        }
      }}
      className={`
        flex items-center gap-3 px-3 min-h-[44px] rounded-md cursor-pointer
        transition-colors group
        ${
          isSelected
            ? "border-l-4 border-l-primary bg-primary/5"
            : "border-l-4 border-l-transparent hover:bg-muted/50"
        }
      `}
      aria-checked={isSelected}
      aria-label={t("catalog.selectList", { name: list.id })}
    >
      <Checkbox
        checked={isSelected}
        onCheckedChange={() => onToggle()}
        onClick={(e) => e.stopPropagation()}
        aria-hidden="true"
        tabIndex={-1}
      />

      <span
        className="font-mono text-sm truncate flex-1"
        title={list.id}
      >
        {list.id}
      </span>

      {list.is_custom && (
        <Badge variant="outline" className="text-xs shrink-0">
          {t("catalog.custom")}
        </Badge>
      )}

      <span className="text-sm text-muted-foreground shrink-0 tabular-nums">
        {t("catalog.domainCount", { count: list.domain_count ?? list.count ?? 0 })}
      </span>

      <Button
        variant="ghost"
        size="sm"
        onClick={(e) => {
          e.stopPropagation();
          onViewDomains();
        }}
        className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
        aria-label={t("catalog.viewDomains", { name: list.id })}
      >
        <Eye className="h-4 w-4" />
        {t("common.view")}
      </Button>
    </div>
  );
}
