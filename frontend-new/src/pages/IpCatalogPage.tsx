import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Search, Plus, Check, X, ChevronDown, ChevronRight, RefreshCw, Loader2 } from "lucide-react";
import { api } from "@/api/client";
import { toast } from "sonner";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { CountryIpInfo } from "@/types";

export function IpCatalogPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<{ country_code: string; display_name: string }[]>([]);
  const [searching, setSearching] = useState(false);
  const [selectedCountries, setSelectedCountries] = useState<Set<string>>(new Set());
  const [selectedOutbound, setSelectedOutbound] = useState("");
  const [customTag, setCustomTag] = useState("");
  const [expandedCountry, setExpandedCountry] = useState<string | null>(null);
  const [countryDetails, setCountryDetails] = useState<CountryIpInfo | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  // Load catalog and rules
  const { data: catalog, isLoading: catalogLoading, error: catalogError, refetch } = useQuery({
    queryKey: ["ip-catalog"],
    queryFn: api.getIpCatalog,
  });

  const { data: rulesData } = useQuery({
    queryKey: ["route-rules"],
    queryFn: api.getRouteRules,
  });

  const availableOutbounds = rulesData?.available_outbounds || [];

  // Set default outbound
  useEffect(() => {
    if (availableOutbounds.length > 0 && !selectedOutbound) {
      setSelectedOutbound(availableOutbounds[0]);
    }
  }, [availableOutbounds, selectedOutbound]);

  // Create rule mutation
  const createRuleMutation = useMutation({
    mutationFn: ({ countries, outbound, tag }: { countries: string[]; outbound: string; tag?: string }) =>
      api.createIpQuickRule(countries, outbound, tag),
    onSuccess: () => {
      toast.success(t("ipCatalog.ruleCreated", { 
        count: selectedCountries.size,
        defaultValue: `Rule created for ${selectedCountries.size} countries` 
      }));
      setSelectedCountries(new Set());
      setCustomTag("");
      queryClient.invalidateQueries({ queryKey: ["route-rules"] });
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  // Search with debounce
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        setSearching(true);
        const res = await api.searchCountries(searchQuery);
        if (!cancelled) {
          setSearchResults(res.results);
        }
      } catch {
        // ignore search errors
      } finally {
        if (!cancelled) {
          setSearching(false);
        }
      }
    }, 300);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [searchQuery]);

  const toggleCountrySelection = (cc: string) => {
    setSelectedCountries((prev) => {
      const next = new Set(prev);
      if (next.has(cc)) {
        next.delete(cc);
      } else {
        next.add(cc);
      }
      return next;
    });
  };

  const loadCountryDetails = async (cc: string) => {
    if (expandedCountry === cc) {
      setExpandedCountry(null);
      setCountryDetails(null);
      return;
    }

    try {
      setLoadingDetails(true);
      setExpandedCountry(cc);
      const details = await api.getCountryIps(cc);
      setCountryDetails(details);
    } catch {
      // ignore
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleCreateRule = () => {
    if (selectedCountries.size === 0 || !selectedOutbound) return;
    
    createRuleMutation.mutate({
      countries: Array.from(selectedCountries),
      outbound: selectedOutbound,
      tag: customTag || undefined,
    });
  };

  // Get countries to display
  const displayCountries = catalog
    ? Object.entries(catalog.countries).sort((a, b) => 
        a[1].display_name.localeCompare(b[1].display_name)
      )
    : [];

  if (catalogLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (catalogError) {
    return (
      <Alert variant="destructive">
        <AlertDescription>
          {(catalogError as Error).message}
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            {t("ipCatalog.title", { defaultValue: "IP Catalog" })}
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            {t("ipCatalog.subtitle", { defaultValue: "Create routing rules based on country IP ranges" })}
            {catalog && (
              <span className="ml-2 text-muted-foreground/70">
                ({t("ipCatalog.countriesCount", { 
                  count: catalog.stats.total_countries,
                  defaultValue: `${catalog.stats.total_countries} countries` 
                })})
              </span>
            )}
          </p>
        </div>
        <Button variant="outline" size="icon" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder={t("ipCatalog.searchCountries", { defaultValue: "Search countries..." })}
          className="pl-10"
        />
        {searching && (
          <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 animate-spin text-muted-foreground" />
        )}
      </div>

      {/* Search Results */}
      {searchResults.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">
              {t("common.searchResults", { defaultValue: "Search Results" })}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {searchResults.map((result) => (
                <Button
                  key={result.country_code}
                  variant={selectedCountries.has(result.country_code) ? "default" : "outline"}
                  size="sm"
                  onClick={() => toggleCountrySelection(result.country_code)}
                >
                  {selectedCountries.has(result.country_code) && <Check className="h-3 w-3 mr-1" />}
                  {result.display_name}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Selected Countries & Create Rule */}
      {selectedCountries.size > 0 && (
        <Card className="border-primary/50 bg-primary/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">
              {t("ipCatalog.selectedCountries", { 
                count: selectedCountries.size,
                defaultValue: `${selectedCountries.size} Countries Selected` 
              })}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {Array.from(selectedCountries).map((cc) => (
                <Badge key={cc} variant="secondary" className="flex items-center gap-1">
                  {catalog?.countries[cc]?.display_name || cc.toUpperCase()}
                  <button
                    onClick={() => toggleCountrySelection(cc)}
                    className="ml-1 hover:text-destructive"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Select value={selectedOutbound} onValueChange={setSelectedOutbound}>
                <SelectTrigger className="w-[200px]">
                  <SelectValue placeholder={t("ipCatalog.selectOutbound", { defaultValue: "Select outbound" })} />
                </SelectTrigger>
                <SelectContent>
                  {availableOutbounds.map((ob) => (
                    <SelectItem key={ob} value={ob}>{ob}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                type="text"
                value={customTag}
                onChange={(e) => setCustomTag(e.target.value)}
                placeholder={t("ipCatalog.customRuleName", { defaultValue: "Custom rule name (optional)" })}
                className="w-[200px]"
              />
              <Button onClick={handleCreateRule} disabled={createRuleMutation.isPending}>
                {createRuleMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Plus className="h-4 w-4 mr-2" />
                )}
                {t("ipCatalog.createRule", { defaultValue: "Create Rule" })}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Countries Grid */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {displayCountries.map(([cc, info]) => (
          <Card
            key={cc}
            className={selectedCountries.has(cc) ? "border-primary/50 bg-primary/5" : ""}
          >
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Checkbox
                    checked={selectedCountries.has(cc)}
                    onCheckedChange={() => toggleCountrySelection(cc)}
                  />
                  <div>
                    <div className="font-medium">{info.display_name}</div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span>{info.ipv4_count.toLocaleString()} IPv4</span>
                      <span>|</span>
                      <span>{info.ipv6_count.toLocaleString()} IPv6</span>
                    </div>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => loadCountryDetails(cc)}
                >
                  {expandedCountry === cc ? (
                    <ChevronDown className="h-4 w-4" />
                  ) : (
                    <ChevronRight className="h-4 w-4" />
                  )}
                </Button>
              </div>

              {/* Sample IPs */}
              {info.sample_ipv4 && info.sample_ipv4.length > 0 && (
                <div className="mt-2 text-xs text-muted-foreground font-mono truncate">
                  {info.sample_ipv4.slice(0, 2).join(", ")}...
                </div>
              )}

              {/* Expanded Details */}
              {expandedCountry === cc && (
                <div className="mt-4 pt-4 border-t">
                  {loadingDetails ? (
                    <div className="flex items-center gap-2 text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      {t("common.loading", { defaultValue: "Loading..." })}
                    </div>
                  ) : countryDetails ? (
                    <div className="space-y-2">
                      <div className="text-xs text-muted-foreground">
                        {t("ipCatalog.recommendedExit", { defaultValue: "Recommended exit" })}: {countryDetails.recommended_exit}
                      </div>
                      <ScrollArea className="h-24">
                        <div className="flex flex-wrap gap-1">
                          {countryDetails.ipv4_cidrs?.slice(0, 50).map((cidr) => (
                            <Badge key={cidr} variant="outline" className="font-mono text-xs">
                              {cidr}
                            </Badge>
                          ))}
                          {(countryDetails.ipv4_cidrs?.length || 0) > 50 && (
                            <span className="text-xs text-muted-foreground">
                              ... {t("ipCatalog.moreItems", { 
                                count: (countryDetails.ipv4_cidrs?.length || 0) - 50,
                                defaultValue: `${(countryDetails.ipv4_cidrs?.length || 0) - 50} more` 
                              })}
                            </span>
                          )}
                        </div>
                      </ScrollArea>
                    </div>
                  ) : null}
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

export default IpCatalogPage;
