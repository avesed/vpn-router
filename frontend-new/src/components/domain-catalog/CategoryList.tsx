import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Input } from "../ui/input";
import { CategoryCard } from "./CategoryCard";
import { AddCatalogRuleDialog } from "./AddCatalogRuleDialog";
import { useCreateQuickRule, useCreateIpQuickRule } from "../../api/hooks/useDomainCatalog";
import { Search } from "lucide-react";

interface CategoryListProps {
  categories: any[];
  type: "domain" | "ip";
}

export function CategoryList({ categories, type }: CategoryListProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<any>(null);

  const createDomainRule = useCreateQuickRule();
  const createIpRule = useCreateIpQuickRule();

  const filteredCategories = categories.filter((cat) => {
    const term = search.toLowerCase();
    return (
      cat.name?.toLowerCase().includes(term) ||
      cat.description?.toLowerCase().includes(term) ||
      cat.id?.toLowerCase().includes(term)
    );
  });

  const searchPlaceholder =
    type === "domain" ? t("catalog.searchDomainLists") : t("catalog.searchCountries");
  const actionLabel =
    type === "domain" ? t("catalog.createRule") : t("catalog.createIpRule");
  const emptyMessage = search
    ? t("catalog.noCategories", { search })
    : t("common.noData");

  const handleAddRule = (outbound: string, tag: string) => {
    if (!selectedCategory) return;

    if (type === "domain") {
      createDomainRule.mutate(
        { listIds: [selectedCategory.id || selectedCategory.name], outbound, tag },
        {
          onSuccess: () => setSelectedCategory(null),
        }
      );
    } else {
      // For IP catalog, assuming category ID is country code
      createIpRule.mutate(
        { countryCodes: [selectedCategory.code || selectedCategory.id], outbound, tag },
        {
          onSuccess: () => setSelectedCategory(null),
        }
      );
    }
  };

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
        {filteredCategories.map((cat) => (
          <CategoryCard
            key={cat.id || cat.code}
            id={cat.id || cat.code}
            name={cat.name || cat.country}
            description={cat.description}
            count={cat.rule_count} // Assuming API returns this if configured
            lists={cat.lists}
            actionLabel={actionLabel}
            onAdd={() => setSelectedCategory(cat)}
          />
        ))}
        {filteredCategories.length === 0 && (
          <div className="col-span-full text-center py-8 text-muted-foreground">
            {emptyMessage}
          </div>
        )}
      </div>

      {selectedCategory && (
        <AddCatalogRuleDialog
          open={!!selectedCategory}
          onOpenChange={(open) => !open && setSelectedCategory(null)}
          categoryName={selectedCategory.name || selectedCategory.country}
          categoryId={selectedCategory.id || selectedCategory.code}
          type={type}
          onSubmit={handleAddRule}
          isSubmitting={isSubmitting}
        />
      )}
    </div>
  );
}
