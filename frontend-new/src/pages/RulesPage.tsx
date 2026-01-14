import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useRouteRules } from "../api/hooks/useRules";
import { RulesList } from "../components/rules/RulesList";
import { RuleEditDialog } from "../components/rules/RuleEditDialog";
import { DefaultOutboundSelect } from "../components/rules/DefaultOutboundSelect";
import { Button } from "../components/ui/button";
import { Plus } from "lucide-react";

export default function RulesPage() {
  const { t } = useTranslation();
  const { data, isLoading, error } = useRouteRules();
  const [showAddDialog, setShowAddDialog] = useState(false);

  if (isLoading) return <div>{t("common.loading")}</div>;
  if (error) return <div>{t("common.error")}: {error.message}</div>;

  const rules = data?.rules || [];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("rules.title")}</h1>
          <p className="text-muted-foreground">
            {t("rules.subtitle")}
          </p>
        </div>
        <Button onClick={() => setShowAddDialog(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t("rules.addRule")}
        </Button>
      </div>

      <DefaultOutboundSelect />

      <div className="space-y-4">
        <h2 className="text-xl font-semibold tracking-tight">{t("rules.title")}</h2>
        <RulesList rules={rules} />
      </div>

      <RuleEditDialog open={showAddDialog} onOpenChange={setShowAddDialog} />
    </div>
  );
}
