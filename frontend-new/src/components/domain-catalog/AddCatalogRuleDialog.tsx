import { useState, useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Label } from "../ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Input } from "../ui/input";
import { Checkbox } from "../ui/checkbox";
import { useAllEgress } from "../../api/hooks/useEgress";
import { Loader2 } from "lucide-react";

interface AddCatalogRuleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  // Original: single category mode (for backward compatibility)
  categoryName?: string;
  categoryId?: string;
  // NEW: multi-list mode
  listIds?: string[];
  listNames?: string[];  // For display
  estimatedDomainCount?: number;
  type: "domain" | "ip";
  onSubmit: (outbound: string, tag: string, separateRules?: boolean) => void;
  isSubmitting: boolean;
}

export function AddCatalogRuleDialog({
  open,
  onOpenChange,
  categoryName,
  categoryId,
  listIds,
  listNames,
  estimatedDomainCount,
  type,
  onSubmit,
  isSubmitting,
}: AddCatalogRuleDialogProps) {
  const { t } = useTranslation();
  const { data: egressData } = useAllEgress();
  const [outbound, setOutbound] = useState<string>("");
  const [tag, setTag] = useState<string>("");
  const [separateRules, setSeparateRules] = useState<boolean>(false);

  // Detect multi-list mode
  const isMultiListMode = listIds && listIds.length > 0;

  // Generate default tag based on mode
  useEffect(() => {
    if (open) {
      if (isMultiListMode && listIds && listIds.length > 0) {
        // Use first list ID or "custom-rule" for multi-list mode
        setTag(listIds[0] ? `rule-${listIds[0]}` : "custom-rule");
      } else if (categoryId) {
        setTag(`rule-${categoryId}`);
      }
      // Reset separate rules checkbox when dialog opens
      setSeparateRules(false);
    }
  }, [open, isMultiListMode, listIds, categoryId]);

  const handleSubmit = () => {
    if (outbound) {
      onSubmit(outbound, tag, isMultiListMode ? separateRules : undefined);
    }
  };

  const outbounds = Array.isArray(egressData) ? egressData : [];
  const actionLabel = type === "domain" ? t("catalog.createRule") : t("catalog.createIpRule");

  // Format the selected lists display for multi-list mode
  const selectedListsDisplay = useMemo(() => {
    if (!isMultiListMode || !listNames || listNames.length === 0) {
      return "";
    }

    const MAX_DISPLAY = 3;
    if (listNames.length <= MAX_DISPLAY) {
      return listNames.join(", ");
    }

    const displayed = listNames.slice(0, MAX_DISPLAY).join(", ");
    const remaining = listNames.length - MAX_DISPLAY;
    return `${displayed} ${t("catalog.andMore", { count: remaining })}`;
  }, [isMultiListMode, listNames, t]);

  // Title and description based on mode
  const dialogTitle = isMultiListMode
    ? t("catalog.createRuleFromSelection")
    : t("catalog.addRuleTitle", { name: categoryName });

  const dialogDescription = isMultiListMode
    ? undefined // We'll show custom content instead
    : t("catalog.addRuleDescription", { name: categoryName });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{dialogTitle}</DialogTitle>
          {dialogDescription && (
            <DialogDescription>
              {dialogDescription}
            </DialogDescription>
          )}
        </DialogHeader>

        <div className="grid gap-4 py-4">
          {/* Multi-list mode info display */}
          {isMultiListMode && (
            <div className="space-y-2 text-sm">
              <div>
                <span className="text-muted-foreground">{t("catalog.selectedListsLabel")}: </span>
                <span className="font-medium">{selectedListsDisplay}</span>
              </div>
              {estimatedDomainCount !== undefined && estimatedDomainCount > 0 && (
                <div className="text-muted-foreground">
                  {t("catalog.estimatedDomains", { count: estimatedDomainCount })}
                </div>
              )}
            </div>
          )}

          <div className="grid gap-2">
            <Label htmlFor="tag">{t("rules.ruleTag")}</Label>
            <Input
              id="tag"
              value={tag}
              onChange={(e) => setTag(e.target.value)}
              placeholder={t("catalog.ruleTagPlaceholder")}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="outbound">{t("rules.outboundLine")}</Label>
            <Select value={outbound} onValueChange={setOutbound}>
              <SelectTrigger id="outbound">
                <SelectValue
                  placeholder={t("common.selectPlaceholder", { item: t("rules.outbound") })}
                />
              </SelectTrigger>
              <SelectContent>
                {outbounds.map((egress) => (
                  <SelectItem key={egress.tag} value={egress.tag}>
                    {egress.tag} ({egress.type})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Separate rules checkbox - only show in multi-list mode with more than 1 list */}
          {isMultiListMode && listIds && listIds.length > 1 && (
            <div className="flex items-center space-x-2">
              <Checkbox
                id="separateRules"
                checked={separateRules}
                onCheckedChange={(checked) => setSeparateRules(checked === true)}
              />
              <Label
                htmlFor="separateRules"
                className="text-sm font-normal cursor-pointer"
              >
                {t("catalog.createSeparateRules")}
              </Label>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button onClick={handleSubmit} disabled={!outbound || isSubmitting}>
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {actionLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
