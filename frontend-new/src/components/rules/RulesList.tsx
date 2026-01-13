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
  const deleteRule = useDeleteCustomRule();

  const handleDelete = (tag: string) => {
    if (!confirm(`Are you sure you want to delete rule ${tag}?`)) return;
    toast.promise(deleteRule.mutateAsync(tag), {
      loading: "Deleting rule...",
      success: "Rule deleted",
      error: "Failed to delete rule",
    });
  };

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Tag</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Target Outbound</TableHead>
            <TableHead>Criteria</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.length === 0 ? (
            <TableRow>
              <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                No custom rules configured.
              </TableCell>
            </TableRow>
          ) : (
            rules.map((rule) => (
              <TableRow key={rule.tag}>
                <TableCell className="font-medium">{rule.tag}</TableCell>
                <TableCell>
                  <Badge variant="secondary">{rule.type || "custom"}</Badge>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{rule.outbound}</Badge>
                </TableCell>
                <TableCell className="max-w-[300px]">
                  <div className="flex flex-wrap gap-1">
                    {rule.domains && rule.domains.length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        {rule.domains.length} domains
                      </span>
                    )}
                    {rule.domain_keywords && rule.domain_keywords.length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        {rule.domain_keywords.length} keywords
                      </span>
                    )}
                    {rule.ip_cidrs && rule.ip_cidrs.length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        {rule.ip_cidrs.length} CIDRs
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
