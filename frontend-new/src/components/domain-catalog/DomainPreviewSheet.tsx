import { useState, useMemo, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Loader2, Search, Globe } from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "../ui/sheet";
import { ScrollArea } from "../ui/scroll-area";
import { Input } from "../ui/input";
import { useDomainList } from "../../api/hooks/useDomainCatalog";

interface DomainPreviewSheetProps {
  listId: string | null;
  listName?: string;
  onClose: () => void;
}

export function DomainPreviewSheet({
  listId,
  listName,
  onClose,
}: DomainPreviewSheetProps) {
  const { t } = useTranslation();
  const [searchTerm, setSearchTerm] = useState("");

  // Reset search state when listId changes (sheet reopens with different list)
  useEffect(() => {
    if (listId) {
      setSearchTerm("");
    }
  }, [listId]);

  const { data, isLoading, isError, error } = useDomainList(listId ?? "");

  // Combine domains and full_domains, removing duplicates
  const allDomains = useMemo(() => {
    if (!data) return [];
    const domainSet = new Set<string>();
    data.domains?.forEach((d) => domainSet.add(d));
    data.full_domains?.forEach((d) => domainSet.add(d));
    return Array.from(domainSet).sort((a, b) => a.localeCompare(b));
  }, [data]);

  // Filter domains based on search term
  const filteredDomains = useMemo(() => {
    if (!searchTerm.trim()) return allDomains;
    const term = searchTerm.toLowerCase();
    return allDomains.filter((domain) => domain.toLowerCase().includes(term));
  }, [allDomains, searchTerm]);

  const isOpen = listId !== null;

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-md flex flex-col">
        <SheetHeader className="space-y-1">
          <SheetTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-muted-foreground" />
            {listName || listId || t("catalog.domainList")}
          </SheetTitle>
          {!isLoading && !isError && (
            <p className="text-sm text-muted-foreground">
              {t("catalog.domainCount", { count: allDomains.length })}
            </p>
          )}
        </SheetHeader>

        <div className="mt-4 flex-1 flex flex-col min-h-0">
          {/* Search Input */}
          <div className="relative mb-4">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              type="search"
              placeholder={t("catalog.searchDomains")}
              className="pl-8"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              disabled={isLoading || isError}
            />
          </div>

          {/* Loading State */}
          {isLoading && (
            <div className="flex-1 flex items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          )}

          {/* Error State */}
          {isError && (
            <div className="flex-1 flex flex-col items-center justify-center text-center px-4">
              <p className="text-destructive font-medium">
                {t("common.loadFailed")}
              </p>
              <p className="text-sm text-muted-foreground mt-1">
                {error instanceof Error ? error.message : t("common.error")}
              </p>
            </div>
          )}

          {/* Empty State */}
          {!isLoading && !isError && allDomains.length === 0 && (
            <div className="flex-1 flex items-center justify-center">
              <p className="text-muted-foreground">{t("common.noData")}</p>
            </div>
          )}

          {/* Domain List */}
          {!isLoading && !isError && allDomains.length > 0 && (
            <>
              {/* Filtered count when searching */}
              {searchTerm && (
                <p className="text-xs text-muted-foreground mb-2">
                  {t("common.searchResults")}: {filteredDomains.length}
                </p>
              )}

              <ScrollArea className="flex-1 -mx-6 px-6">
                <div className="space-y-1 pb-4">
                  {filteredDomains.length > 0 ? (
                    filteredDomains.map((domain) => (
                      <div
                        key={domain}
                        className="py-1.5 px-2 rounded text-sm font-mono hover:bg-muted transition-colors truncate"
                        title={domain}
                      >
                        {domain}
                      </div>
                    ))
                  ) : (
                    <div className="py-8 text-center text-muted-foreground">
                      {t("common.noMatchingResults")}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
