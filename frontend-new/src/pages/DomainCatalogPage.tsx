import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { CategoryList } from "../components/domain-catalog/CategoryList";
import { useDomainCatalog, useIpCatalog } from "../api/hooks/useDomainCatalog";
import { Loader2 } from "lucide-react";

export default function DomainCatalogPage() {
  const { data: domainCatalog, isLoading: isDomainLoading } = useDomainCatalog();
  const { data: ipCatalog, isLoading: isIpLoading } = useIpCatalog();

  // Transform data
  const domainList = domainCatalog?.categories 
    ? Object.entries(domainCatalog.categories).map(([id, cat]) => ({
        id,
        ...cat
      }))
    : [];
  
  const ipList = ipCatalog?.countries 
    ? Object.values(ipCatalog.countries).map(country => ({
        id: country.country_code,
        code: country.country_code,
        name: country.display_name || country.country_name,
        description: `${country.ipv4_count} IPv4 ranges, ${country.ipv6_count} IPv6 ranges`,
        ...country
      }))
    : [];

  if (isDomainLoading || isIpLoading) {
    return (
      <div className="flex items-center justify-center h-full p-8">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Domain & IP Catalog</h1>
        <p className="text-muted-foreground">
          Browse and create routing rules from predefined lists of domains and IP ranges.
        </p>
      </div>

      <Tabs defaultValue="geosite" className="space-y-4">
        <TabsList>
          <TabsTrigger value="geosite">Domain Categories (Geosite)</TabsTrigger>
          <TabsTrigger value="geoip">IP Categories (GeoIP)</TabsTrigger>
        </TabsList>
        
        <TabsContent value="geosite" className="space-y-4">
          <CategoryList categories={domainList} type="domain" />
        </TabsContent>
        
        <TabsContent value="geoip" className="space-y-4">
          <CategoryList categories={ipList} type="ip" />
        </TabsContent>
      </Tabs>
    </div>
  );
}
