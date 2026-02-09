import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { CategoryList } from "../components/domain-catalog/CategoryList";
import { useDomainCatalog, useIpCatalog } from "../api/hooks/useDomainCatalog";
import { Loader2 } from "lucide-react";

export default function DomainCatalogPage() {
  const { t } = useTranslation();
  const location = useLocation();
  const { data: domainCatalog, isLoading: isDomainLoading } = useDomainCatalog();
  const { data: ipCatalog, isLoading: isIpLoading } = useIpCatalog();
  const initialTab = location.pathname.includes("ip-catalog") ? "geoip" : "geosite";
  const [activeTab, setActiveTab] = useState(initialTab);

  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab]);

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
        description: t("catalog.ipRangeSummary", {
          ipv4: country.ipv4_count,
          ipv6: country.ipv6_count,
        }),
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
        <h1 className="text-3xl font-bold tracking-tight">{t("catalog.title")}</h1>
        <p className="text-muted-foreground">
          {t("catalog.subtitle")}
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="geosite">{t("catalog.byDomain")}</TabsTrigger>
          <TabsTrigger value="geoip">{t("catalog.byIp")}</TabsTrigger>
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
