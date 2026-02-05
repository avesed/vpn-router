import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../ui/card";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { Checkbox } from "../ui/checkbox";
import { ChevronDown } from "lucide-react";
import { ListItemRow } from "./ListItemRow";
import type { DomainListSummary } from "../../types";

interface CategoryCardProps {
  id: string;
  name: string;
  description?: string;
  count?: number;
  tags?: string[];
  lists?: DomainListSummary[];
  // Selection props
  selectedLists?: Set<string>;
  onToggleList?: (listId: string) => void;
  onToggleCategory?: (lists: DomainListSummary[]) => void;
  // Domain preview handler
  onViewDomains?: (listId: string, listName: string) => void;
  // Auto-expand when search matches list names
  autoExpand?: boolean;
  // IP catalog mode - card itself is selectable (no nested lists)
  isDirectlySelectable?: boolean;
  onToggleSelf?: () => void;
}

export function CategoryCard({
  id,
  name,
  description,
  count,
  tags,
  lists,
  selectedLists,
  onToggleList,
  onToggleCategory,
  onViewDomains,
  autoExpand,
  isDirectlySelectable,
  onToggleSelf,
}: CategoryCardProps) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);

  // React to autoExpand prop changes (from search filtering)
  useEffect(() => {
    if (autoExpand) {
      setExpanded(true);
    }
  }, [autoExpand]);

  // Calculate selection state for this category
  const categoryListIds = lists?.map((l) => l.id) ?? [];
  const selectedCount = categoryListIds.filter((id) => selectedLists?.has(id)).length;
  const allSelected = lists && lists.length > 0 && selectedCount === lists.length;
  const someSelected = selectedCount > 0 && selectedCount < (lists?.length ?? 0);

  // For IP catalog: check if this card itself is selected
  const isSelfSelected = isDirectlySelectable && selectedLists?.has(id);

  const handleToggleCategory = () => {
    if (lists && onToggleCategory) {
      onToggleCategory(lists);
    }
  };

  const handleViewDomains = (listId: string, listName: string) => {
    if (onViewDomains) {
      onViewDomains(listId, listName);
    }
  };

  const handleCardClick = () => {
    if (isDirectlySelectable && onToggleSelf) {
      onToggleSelf();
    }
  };

  return (
    <Card
      className={`flex flex-col h-full ${isDirectlySelectable ? "cursor-pointer transition-colors hover:bg-muted/50" : ""} ${isSelfSelected ? "border-primary bg-primary/5" : ""}`}
      onClick={isDirectlySelectable ? handleCardClick : undefined}
    >
      <CardHeader className="pb-2">
        <div className="flex justify-between items-start">
          <div className="flex items-center gap-3">
            {isDirectlySelectable && (
              <Checkbox
                checked={isSelfSelected}
                onCheckedChange={() => onToggleSelf?.()}
                onClick={(e) => e.stopPropagation()}
                aria-label={t("catalog.selectCountry", { name })}
              />
            )}
            <CardTitle className="text-lg">{name}</CardTitle>
          </div>
          {count !== undefined && (
            <Badge variant="secondary" className="ml-2">
              {t("catalog.ruleCount", { count })}
            </Badge>
          )}
        </div>
        {description && <CardDescription className="line-clamp-2">{description}</CardDescription>}
      </CardHeader>
      <CardContent className="flex-grow">
        <div className="flex flex-wrap gap-1 mt-2">
          {tags?.map((tag) => (
            <Badge key={tag} variant="outline" className="text-xs">
              {tag}
            </Badge>
          ))}
        </div>

        {lists && lists.length > 0 && (
          <div className="mt-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setExpanded(!expanded)}
              className="w-full justify-between px-0 hover:bg-transparent"
            >
              <span className="text-sm font-medium">
                {t("catalog.subLists", { count: lists.length })}
                {selectedCount > 0 && (
                  <span className="ml-2 text-muted-foreground">
                    ({t("catalog.selectedCount", { count: selectedCount })})
                  </span>
                )}
              </span>
              <ChevronDown className={`h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`} />
            </Button>
            {expanded && (
              <div className="mt-2 space-y-1 max-h-60 overflow-y-auto">
                {/* Select all row */}
                {onToggleCategory && (
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={handleToggleCategory}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        handleToggleCategory();
                      }
                    }}
                    className="flex items-center gap-3 px-3 py-2 rounded-md cursor-pointer hover:bg-muted/50 border-b mb-1"
                  >
                    <Checkbox
                      checked={allSelected}
                      ref={(el) => {
                        if (el) {
                          // Set indeterminate state for partial selection
                          (el as HTMLButtonElement & { indeterminate?: boolean }).indeterminate = someSelected;
                        }
                      }}
                      onCheckedChange={handleToggleCategory}
                      onClick={(e) => e.stopPropagation()}
                      aria-label={t("catalog.selectAll")}
                    />
                    <span className="text-sm font-medium">
                      {t("catalog.selectAll")}
                    </span>
                  </div>
                )}
                {/* List items */}
                {lists.map((list) => (
                  <ListItemRow
                    key={list.id}
                    list={list}
                    isSelected={selectedLists?.has(list.id) ?? false}
                    onToggle={() => onToggleList?.(list.id)}
                    onViewDomains={() => handleViewDomains(list.id, list.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
