import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useRouteRules } from "../api/hooks/useRules";
import { useRulesIgnoreSettings } from "../api/hooks/useUsers";
import { useAuth } from "../providers/AuthProvider";
import { RulesList } from "../components/rules/RulesList";
import { RuleSetsSection } from "../components/rules/RuleSetsSection";
import { RuleEditDialog } from "../components/rules/RuleEditDialog";
import { DefaultOutboundSelect } from "../components/rules/DefaultOutboundSelect";
import { Button } from "../components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Plus, AlertTriangle } from "lucide-react";

export default function RulesPage() {
  const { t } = useTranslation();
  const { user, isAdmin } = useAuth();
  const { data, isLoading, error } = useRouteRules();
  const { data: rulesIgnoreSettings } = useRulesIgnoreSettings();
  const [showAddDialog, setShowAddDialog] = useState(false);

  if (isLoading) return <div>{t("common.loading")}</div>;
  if (error) return <div>{t("common.error")}: {error.message}</div>;

  const rules = data?.rules || [];
  const ruleSets = data?.rule_sets || [];
  const availableOutbounds = data?.available_outbounds || [];

  // Check if current user's rules are being ignored
  const isRulesIgnored = !isAdmin && (
    rulesIgnoreSettings?.ignore_all_user_rules ||
    (user as any)?.rules_ignored
  );

  return (
    <div className="space-y-6">
      {/* Warning when rules are ignored */}
      {isRulesIgnored && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>{t("rules.rulesIgnoredTitle")}</AlertTitle>
          <AlertDescription>
            {rulesIgnoreSettings?.ignore_all_user_rules
              ? t("rules.rulesIgnoredGlobalDesc")
              : t("rules.rulesIgnoredUserDesc")}
          </AlertDescription>
        </Alert>
      )}

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

      {/* Rule Sets Section - shown above individual rules */}
      <RuleSetsSection ruleSets={ruleSets} availableOutbounds={availableOutbounds} />

      <div className="space-y-4">
        <h2 className="text-xl font-semibold tracking-tight">{t("rules.title")}</h2>
        <RulesList rules={rules} availableOutbounds={availableOutbounds} />
      </div>

      <RuleEditDialog open={showAddDialog} onOpenChange={setShowAddDialog} availableOutbounds={availableOutbounds} />
    </div>
  );
}
