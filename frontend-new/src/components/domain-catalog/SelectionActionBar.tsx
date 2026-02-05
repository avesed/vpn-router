import { useTranslation } from "react-i18next";
import { Button } from "../ui/button";
import { cn } from "@/lib/utils";
import { X, Plus } from "lucide-react";

interface SelectionActionBarProps {
  selectedCount: number;
  estimatedDomainCount: number;
  onClear: () => void;
  onCreateRule: () => void;
}

export function SelectionActionBar({
  selectedCount,
  estimatedDomainCount,
  onClear,
  onCreateRule,
}: SelectionActionBarProps) {
  const { t } = useTranslation();

  // Don't render if nothing is selected
  if (selectedCount <= 0) {
    return null;
  }

  return (
    <div
      role="region"
      aria-label={t("catalog.selectionActions", { defaultValue: "Selection actions" })}
      className={cn(
        // Base styles
        "fixed left-4 right-4 z-40",
        "bg-primary text-primary-foreground",
        "rounded-lg shadow-lg border border-primary-foreground/10",
        "px-4 py-3",
        "flex items-center justify-between gap-3",
        // Entrance animation with reduced motion support
        "motion-safe:animate-in motion-safe:slide-in-from-bottom motion-safe:duration-300",
        "motion-reduce:transition-none",
        // Mobile: above MobileBottomNav (h-16 = 64px + safe area, so use 80px)
        "bottom-20",
        // Desktop: normal bottom position
        "md:bottom-4 md:left-auto md:right-4 md:max-w-md"
      )}
    >
      {/* Selection info */}
      <div
        className="flex-1 min-w-0"
        aria-live="polite"
        aria-atomic="true"
      >
        <span className="text-sm font-medium">
          {t("catalog.listsSelected", {
            count: selectedCount,
            defaultValue: `${selectedCount} lists selected`
          })}
        </span>
        <span className="text-sm text-primary-foreground/80 ml-1">
          {t("catalog.estimatedDomains", {
            count: estimatedDomainCount,
            defaultValue: `(~${estimatedDomainCount.toLocaleString()} domains)`
          })}
        </span>
      </div>

      {/* Action buttons */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <Button
          variant="ghost"
          size="sm"
          onClick={onClear}
          className="text-primary-foreground hover:bg-primary-foreground/20 hover:text-primary-foreground"
          aria-label={t("common.clear", { defaultValue: "Clear" })}
        >
          <X className="h-4 w-4 mr-1" aria-hidden="true" />
          <span className="hidden sm:inline">
            {t("common.clear", { defaultValue: "Clear" })}
          </span>
        </Button>
        <Button
          variant="secondary"
          size="sm"
          onClick={onCreateRule}
          className="bg-primary-foreground text-primary hover:bg-primary-foreground/90"
        >
          <Plus className="h-4 w-4 mr-1" aria-hidden="true" />
          {t("catalog.createRule", { defaultValue: "Create Rule" })}
        </Button>
      </div>
    </div>
  );
}
