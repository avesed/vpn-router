import { useState, useCallback, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Input } from "../ui/input";
import { CategoryCard } from "./CategoryCard";
import { AddCatalogRuleDialog } from "./AddCatalogRuleDialog";
import { SelectionActionBar } from "./SelectionActionBar";
import { DomainPreviewSheet } from "./DomainPreviewSheet";
import { useCreateQuickRule, useCreateIpQuickRule } from "../../api/hooks/useDomainCatalog";
import { Search } from "lucide-react";
import type { DomainListSummary } from "../../types";

/**
 * Represents a category with its associated lists for the catalog view.
 * This interface supports both domain catalog categories and IP catalog countries.
 */
export interface CategoryWithLists {
  id: string;
  name?: string;
  description?: string;
  code?: string;
  country?: string;
  lists?: DomainListSummary[];
  rule_count?: number;
}

interface CategoryListProps {
  categories: CategoryWithLists[];
  type: "domain" | "ip";
}

export function CategoryList({ categories, type }: CategoryListProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [selectedLists, setSelectedLists] = useState<Set<string>>(new Set());

  // State for domain preview sheet
  const [previewListId, setPreviewListId] = useState<string | null>(null);
  const [previewListName, setPreviewListName] = useState<string>("");

  // State for multi-list rule dialog
  const [showMultiListDialog, setShowMultiListDialog] = useState(false);

  const createDomainRule = useCreateQuickRule();
  const createIpRule = useCreateIpQuickRule();

  // Toggle individual list selection
  const toggleList = useCallback((listId: string) => {
    setSelectedLists((prev) => {
      const next = new Set(prev);
      if (next.has(listId)) {
        next.delete(listId);
      } else {
        next.add(listId);
      }
      return next;
    });
  }, []);

  // Toggle all lists in a category
  const toggleCategory = useCallback(
    (categoryLists: DomainListSummary[]) => {
      setSelectedLists((prev) => {
        const next = new Set(prev);
        const listIds = categoryLists.map((l) => l.id);
        const allSelected = listIds.every((id) => prev.has(id));

        if (allSelected) {
          // Deselect all lists in this category
          listIds.forEach((id) => next.delete(id));
        } else {
          // Select all lists in this category
          listIds.forEach((id) => next.add(id));
        }
        return next;
      });
    },
    []
  );

  // Clear all selections
  const clearSelection = useCallback(() => {
    setSelectedLists(new Set());
  }, []);

  // Calculate estimated domain count from selected lists
  const estimatedDomainCount = useMemo(() => {
    if (selectedLists.size === 0) return 0;

    let total = 0;
    for (const cat of categories) {
      if (cat.lists) {
        for (const list of cat.lists as DomainListSummary[]) {
          if (selectedLists.has(list.id)) {
            total += list.domain_count ?? list.count ?? 0;
          }
        }
      }
    }
    return total;
  }, [selectedLists, categories]);

  // Enhanced search that filters by category name/description AND list names
  const filteredCategories = useMemo(() => {
    if (!search) {
      return categories.map((cat) => ({ ...cat, autoExpand: false }));
    }
    const term = search.toLowerCase();

    return categories
      .map((cat) => ({
        ...cat,
        matchingLists:
          cat.lists?.filter((list: DomainListSummary) =>
            list.id.toLowerCase().includes(term)
          ) || [],
        categoryMatches:
          cat.name?.toLowerCase().includes(term) ||
          cat.description?.toLowerCase().includes(term) ||
          cat.id?.toLowerCase().includes(term),
      }))
      .filter((cat) => cat.categoryMatches || cat.matchingLists.length > 0)
      .map((cat) => ({
        ...cat,
        // Auto-expand categories with matching lists (but not matching category name)
        autoExpand: !cat.categoryMatches && cat.matchingLists.length > 0,
      }));
  }, [categories, search]);

  const searchPlaceholder =
    type === "domain" ? t("catalog.searchDomainLists") : t("catalog.searchCountries");
  const emptyMessage = search
    ? t("catalog.noCategories", { search })
    : t("common.noData");

  // Handler for viewing domains in a list
  const handleViewDomains = useCallback((listId: string, listName: string) => {
    setPreviewListId(listId);
    setPreviewListName(listName);
  }, []);

  // Handler for creating rule from multi-list selection
  const handleCreateRuleFromSelection = useCallback(() => {
    setShowMultiListDialog(true);
  }, []);

  // Get list names for selected lists (for dialog display)
  const getSelectedListNames = useCallback(() => {
    const names: string[] = [];
    for (const cat of categories) {
      if (cat.lists) {
        for (const list of cat.lists as DomainListSummary[]) {
          if (selectedLists.has(list.id)) {
            names.push(list.id);
          }
        }
      }
    }
    return names;
  }, [categories, selectedLists]);

  // Handler for multi-list rule submission
  const handleMultiListSubmit = useCallback(
    async (outbound: string, tag: string, separateRules?: boolean) => {
      const listIds = Array.from(selectedLists);

      if (type === "domain") {
        if (separateRules && listIds.length > 1) {
          // Create separate rules for each list using Promise.allSettled for proper error handling
          const results = await Promise.allSettled(
            listIds.map((listId) =>
              createDomainRule.mutateAsync({
                listIds: [listId],
                outbound,
                tag: `${tag}-${listId}`,
              })
            )
          );

          const successes = results.filter((r) => r.status === "fulfilled").length;
          const failures = results.filter((r) => r.status === "rejected").length;

          if (failures > 0 && successes > 0) {
            toast.warning(t("catalog.partialSuccess", { successes, failures }));
          } else if (failures > 0 && successes === 0) {
            toast.error(t("common.createFailed"));
          } else if (successes > 0) {
            toast.success(t("catalog.batchSuccess", { count: successes }));
          }

          setShowMultiListDialog(false);
          clearSelection();
        } else {
          // Create single merged rule
          createDomainRule.mutate(
            { listIds, outbound, tag },
            {
              onSuccess: () => {
                toast.success(t("catalog.ruleCreated"));
                setShowMultiListDialog(false);
                clearSelection();
              },
              onError: (error: Error) => {
                toast.error(t("common.createFailed") + ": " + error.message);
              },
            }
          );
        }
      } else {
        // IP catalog - use country codes
        const countryCodes = listIds; // For IP catalog, listIds are country codes
        if (separateRules && countryCodes.length > 1) {
          // Create separate rules for each country using Promise.allSettled for proper error handling
          const results = await Promise.allSettled(
            countryCodes.map((code) =>
              createIpRule.mutateAsync({
                countryCodes: [code],
                outbound,
                tag: `${tag}-${code}`,
              })
            )
          );

          const successes = results.filter((r) => r.status === "fulfilled").length;
          const failures = results.filter((r) => r.status === "rejected").length;

          if (failures > 0 && successes > 0) {
            toast.warning(t("catalog.partialSuccess", { successes, failures }));
          } else if (failures > 0 && successes === 0) {
            toast.error(t("common.createFailed"));
          } else if (successes > 0) {
            toast.success(t("catalog.batchSuccess", { count: successes }));
          }

          setShowMultiListDialog(false);
          clearSelection();
        } else {
          createIpRule.mutate(
            { countryCodes, outbound, tag },
            {
              onSuccess: () => {
                toast.success(t("catalog.ruleCreated"));
                setShowMultiListDialog(false);
                clearSelection();
              },
              onError: (error: Error) => {
                toast.error(t("common.createFailed") + ": " + error.message);
              },
            }
          );
        }
      }
    },
    [selectedLists, type, createDomainRule, createIpRule, clearSelection, t]
  );

  const isSubmitting = createDomainRule.isPending || createIpRule.isPending;

  return (
    <div className="space-y-4">
      <div className="relative">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          type="search"
          placeholder={searchPlaceholder}
          className="pl-8"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filteredCategories.map((cat) => {
          const cardId = cat.id || cat.code || "";
          return (
            <CategoryCard
              key={cardId || "unknown"}
              id={cardId}
              name={cat.name || cat.country || ""}
              description={cat.description}
              count={cat.rule_count}
              lists={cat.lists}
              selectedLists={selectedLists}
              onToggleList={toggleList}
              onToggleCategory={toggleCategory}
              onViewDomains={handleViewDomains}
              autoExpand={cat.autoExpand}
              // IP catalog mode: card itself is selectable (no nested lists)
              isDirectlySelectable={type === "ip"}
              onToggleSelf={() => toggleList(cardId)}
            />
          );
        })}
        {filteredCategories.length === 0 && (
          <div className="col-span-full text-center py-8 text-muted-foreground">
            {emptyMessage}
          </div>
        )}
      </div>

      {/* Multi-list selection rule dialog */}
      {showMultiListDialog && (
        <AddCatalogRuleDialog
          open={showMultiListDialog}
          onOpenChange={setShowMultiListDialog}
          type={type}
          onSubmit={handleMultiListSubmit}
          isSubmitting={isSubmitting}
          listIds={Array.from(selectedLists)}
          listNames={getSelectedListNames()}
          estimatedDomainCount={estimatedDomainCount}
        />
      )}

      {/* Domain preview sheet */}
      <DomainPreviewSheet
        listId={previewListId}
        listName={previewListName}
        onClose={() => {
          setPreviewListId(null);
          setPreviewListName("");
        }}
      />

      {/* Selection action bar (fixed at bottom) */}
      <SelectionActionBar
        selectedCount={selectedLists.size}
        estimatedDomainCount={estimatedDomainCount}
        onClear={clearSelection}
        onCreateRule={handleCreateRuleFromSelection}
      />
    </div>
  );
}

// Export selection utilities for use by parent components
export type { DomainListSummary };
export { type CategoryListProps };
