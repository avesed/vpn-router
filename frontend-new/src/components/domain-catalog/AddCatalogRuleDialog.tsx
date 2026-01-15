import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Label } from "../ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Input } from "../ui/input";
import { useAllEgress } from "../../api/hooks/useEgress";
import { Loader2 } from "lucide-react";

interface AddCatalogRuleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  categoryName: string;
  categoryId: string;
  type: "domain" | "ip";
  onSubmit: (outbound: string, tag: string) => void;
  isSubmitting: boolean;
}

export function AddCatalogRuleDialog({
  open,
  onOpenChange,
  categoryName,
  categoryId,
  type,
  onSubmit,
  isSubmitting,
}: AddCatalogRuleDialogProps) {
  const { t } = useTranslation();
  const { data: egressData } = useAllEgress();
  const [outbound, setOutbound] = useState<string>("");
  const [tag, setTag] = useState<string>(`rule-${categoryId}`);

  const handleSubmit = () => {
    if (outbound) {
      onSubmit(outbound, tag);
    }
  };

  const outbounds = Array.isArray(egressData) ? egressData : [];
  const actionLabel = type === "domain" ? t("catalog.createRule") : t("catalog.createIpRule");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("catalog.addRuleTitle", { name: categoryName })}</DialogTitle>
          <DialogDescription>
            {t("catalog.addRuleDescription", { name: categoryName })}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-4">
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
