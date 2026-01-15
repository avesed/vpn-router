import { useTranslation } from "react-i18next";
import type { RouteRule } from "../../types";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { Trash2 } from "lucide-react";
import { useDeleteCustomRule } from "../../api/hooks/useRules";
import { toast } from "sonner";

interface RulesListProps {
  rules: RouteRule[];
}

export function RulesList({ rules }: RulesListProps) {
  const { t } = useTranslation();
  const deleteRule = useDeleteCustomRule();

  const handleDelete = (tag: string) => {
    if (!confirm(t("rules.confirmDeleteRule", { name: tag }))) return;
    toast.promise(deleteRule.mutateAsync(tag), {
      loading: t("rules.deletingRule"),
      success: t("rules.ruleDeleted", { name: tag }),
      error: t("common.deleteFailed"),
    });
  };

  const getTypeLabel = (type?: string) => {
    if (!type || type === "custom") return t("common.custom");
    if (type === "protocol") return t("rules.protocolMatching");
    return type;
  };

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
            <TableRow>
              <TableHead>{t("rules.ruleTag")}</TableHead>
              <TableHead>{t("common.type")}</TableHead>
              <TableHead>{t("rules.outboundLine")}</TableHead>
              <TableHead>{t("rules.criteria")}</TableHead>
              <TableHead className="text-right">{t("common.actions")}</TableHead>
            </TableRow>

        </TableHeader>
        <TableBody>
          {rules.length === 0 ? (
            <TableRow>
              <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                {t("rules.noRulesConfigured")}
              </TableCell>
            </TableRow>
          ) : (
            rules.map((rule) => (
              <TableRow key={rule.tag}>
                <TableCell className="font-medium">{rule.tag}</TableCell>
                <TableCell>
                  <Badge variant="secondary">{getTypeLabel(rule.type)}</Badge>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{rule.outbound}</Badge>
                </TableCell>
                <TableCell className="max-w-[300px]">
                  <div className="flex flex-wrap gap-1">
                    {rule.domains && rule.domains.length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        {t("rules.domainSuffixCount", { count: rule.domains.length })}
                      </span>
                    )}
                    {rule.domain_keywords && rule.domain_keywords.length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        {t("rules.domainKeywordCount", { count: rule.domain_keywords.length })}
                      </span>
                    )}
                    {rule.ip_cidrs && rule.ip_cidrs.length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        {t("rules.ipCidrCount", { count: rule.ip_cidrs.length })}
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="text-destructive hover:text-destructive"
                    onClick={() => handleDelete(rule.tag)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
