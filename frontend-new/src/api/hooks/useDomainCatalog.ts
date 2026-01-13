import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { toast } from "sonner";

export const domainCatalogKeys = {
  all: ["domain-catalog"] as const,
  categories: ["domain-catalog", "categories"] as const,
  category: (id: string) => ["domain-catalog", "categories", id] as const,
  lists: (id: string) => ["domain-catalog", "lists", id] as const,
  search: (query: string) => ["domain-catalog", "search", query] as const,
  ipCatalog: ["ip-catalog"] as const,
  countryIps: (code: string) => ["ip-catalog", "country", code] as const,
};

export function useDomainCategories() {
  return useQuery({
    queryKey: domainCatalogKeys.categories,
    queryFn: api.getDomainCategories,
  });
}

export function useDomainCatalog() {
  return useQuery({
    queryKey: domainCatalogKeys.all,
    queryFn: api.getDomainCatalog,
  });
}

export function useDomainCategory(categoryId: string) {
  return useQuery({
    queryKey: domainCatalogKeys.category(categoryId),
    queryFn: () => api.getDomainCategory(categoryId),
    enabled: !!categoryId,
  });
}

export function useDomainList(listId: string) {
  return useQuery({
    queryKey: domainCatalogKeys.lists(listId),
    queryFn: () => api.getDomainList(listId),
    enabled: !!listId,
  });
}

export function useSearchDomainLists(query: string) {
  return useQuery({
    queryKey: domainCatalogKeys.search(query),
    queryFn: () => api.searchDomainLists(query),
    enabled: query.length > 2,
  });
}

export function useCreateQuickRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ listIds, outbound, tag }: { listIds: string[]; outbound: string; tag?: string }) =>
      api.createQuickRule(listIds, outbound, tag),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rules"] });
      toast.success("Domain rule created successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to create domain rule: ${error.message}`);
    },
  });
}

// IP Catalog Hooks
export function useIpCatalog() {
  return useQuery({
    queryKey: domainCatalogKeys.ipCatalog,
    queryFn: api.getIpCatalog,
  });
}

export function useCreateIpQuickRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ countryCodes, outbound, tag, ipv4Only }: { countryCodes: string[]; outbound: string; tag?: string; ipv4Only?: boolean }) =>
      api.createIpQuickRule(countryCodes, outbound, tag, ipv4Only),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rules"] });
      toast.success("IP rule created successfully");
    },
    onError: (error: Error) => {
      toast.error(`Failed to create IP rule: ${error.message}`);
    },
  });
}
