import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useDefaultOutbound, useSwitchDefaultOutbound } from "../../api/hooks/useRules";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Label } from "../ui/label";
import { toast } from "sonner";

export function DefaultOutboundSelect() {
  const { t } = useTranslation();
  const { data, isLoading } = useDefaultOutbound();
  const switchOutbound = useSwitchDefaultOutbound();
  const [value, setValue] = useState("");

  useEffect(() => {
    if (data?.outbound) {
      setValue(data.outbound);
    }
  }, [data]);

  const handleValueChange = (newValue: string) => {
    setValue(newValue);
    toast.promise(switchOutbound.mutateAsync(newValue), {
      loading: t("rules.switchingDefaultOutbound"),
      success: t("rules.switchSuccess"),
      error: t("rules.switchFailed"),
    });
  };

  if (isLoading || !data) return <div>{t("common.loading")}</div>;

  return (
    <div className="flex items-center gap-4 p-4 border rounded-lg bg-card">
      <Label className="min-w-[120px]">{t("rules.defaultOutbound")}</Label>
      <Select value={value} onValueChange={handleValueChange} disabled={switchOutbound.isPending}>
        <SelectTrigger className="w-[300px]">
          <SelectValue
            placeholder={t("common.selectPlaceholder", { item: t("rules.defaultOutbound") })}
          />
        </SelectTrigger>
        <SelectContent>
          {data.available_outbounds.map((outbound) => (
            <SelectItem key={outbound} value={outbound}>
              {outbound}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-sm text-muted-foreground">
        {t("rules.defaultOutboundDesc")}
      </p>
    </div>
  );
}
