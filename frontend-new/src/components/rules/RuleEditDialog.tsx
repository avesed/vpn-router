import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useAddCustomRule } from "../../api/hooks/useRules";
import { useAllEgress } from "../../api/hooks/useEgress";
import { useDomainCatalog } from "../../api/hooks/useDomainCatalog";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "../ui/form";
import { Input } from "../ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Textarea } from "../ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { Badge } from "../ui/badge";
import { Checkbox } from "../ui/checkbox";
import { toast } from "sonner";

const formSchema = z.object({
  tag: z.string().min(1, "Tag is required"),
  outbound: z.string().min(1, "Outbound is required"),
  domains: z.string().optional(),
  domainKeywords: z.string().optional(),
  ipCidrs: z.string().optional(),
});

interface RuleEditDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function RuleEditDialog({ open, onOpenChange }: RuleEditDialogProps) {
  const { t } = useTranslation();
  const addRule = useAddCustomRule();
  const { data: allEgress } = useAllEgress();
  const { data: domainCatalog } = useDomainCatalog();
  const [selectedCatalogLists, setSelectedCatalogLists] = useState<string[]>([]);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      tag: "",
      outbound: "",
      domains: "",
      domainKeywords: "",
      ipCidrs: "",
    },
  });

  const onSubmit = (values: z.infer<typeof formSchema>) => {
    let domains = values.domains ? values.domains.split("\n").filter(Boolean) : [];
    const domainKeywords = values.domainKeywords ? values.domainKeywords.split("\n").filter(Boolean) : undefined;
    const ipCidrs = values.ipCidrs ? values.ipCidrs.split("\n").filter(Boolean) : undefined;

    // Add catalog lists as domains with geosite: prefix
    if (selectedCatalogLists.length > 0) {
      const catalogDomains = selectedCatalogLists.map(listId => `geosite:${listId}`);
      domains = [...domains, ...catalogDomains];
    }

    toast.promise(
      addRule.mutateAsync({
        tag: values.tag,
        outbound: values.outbound,
        domains: domains.length > 0 ? domains : undefined,
        domainKeywords,
        ipCidrs,
      }),
      {
        loading: t("rules.addingRule"),
        success: () => {
          onOpenChange(false);
          form.reset();
          setSelectedCatalogLists([]);
          return t("rules.addRuleSuccess");
        },
        error: (err) => t("rules.addRuleFailed", { message: err.message }),
      }
    );
  };

  const availableOutbounds = allEgress
    ? [
        ...allEgress.pia.map((e) => e.tag),
        ...allEgress.custom.map((e) => e.tag),
        ...allEgress.direct.map((e) => e.tag),
        ...(allEgress.warp || []).map((e) => e.tag),
        ...allEgress.openvpn.map((e) => e.tag),
        ...allEgress.v2ray.map((e) => e.tag),
      ]
    : [];

  // Get domain catalog categories
  const catalogCategories = domainCatalog?.categories ? Object.entries(domainCatalog.categories) : [];

  const handleCatalogListToggle = (listId: string) => {
    setSelectedCatalogLists(prev =>
      prev.includes(listId) ? prev.filter(id => id !== listId) : [...prev, listId]
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>{t("rules.addNewRule")}</DialogTitle>
          <DialogDescription>{t("rules.addRuleDescription")}</DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4 flex-1 overflow-auto px-1">
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="tag"
                render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t("rules.ruleTag")}</FormLabel>
                      <FormControl>
                        <Input placeholder={t("rules.ruleTagPlaceholder")} {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>

                )}
              />
              <FormField
                control={form.control}
                name="outbound"
                render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t("rules.outboundLine")}</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue
                              placeholder={t("common.selectPlaceholder", { item: t("rules.outbound") })}
                            />
                          </SelectTrigger>
                        </FormControl>

                      <SelectContent>
                        {availableOutbounds.map((tag) => (
                          <SelectItem key={tag} value={tag}>
                            {tag}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <Tabs defaultValue="manual" className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="manual">{t("rules.manualInput")}</TabsTrigger>
                <TabsTrigger value="catalog">
                  {t("rules.domainCatalogTab", { count: selectedCatalogLists.length })}
                </TabsTrigger>
              </TabsList>

              <TabsContent value="manual" className="space-y-4 mt-4">
                <FormField
                  control={form.control}
                  name="domains"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t("rules.domainSuffix")}</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder={t("rules.domainSuffixPlaceholder")}
                          className="h-20"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="domainKeywords"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t("rules.domainKeyword")}</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder={t("rules.domainKeywordPlaceholder")}
                          className="h-20"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="ipCidrs"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t("rules.ipCidr")}</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder={t("rules.ipCidrPlaceholder")}
                          className="h-20"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </TabsContent>

              <TabsContent value="catalog" className="space-y-4 mt-4">
                <div>
                  <FormLabel>{t("rules.catalogSelectTitle")}</FormLabel>
                  <p className="text-sm text-muted-foreground mb-3">
                    {t("rules.catalogSelectDescription", { count: selectedCatalogLists.length })}
                  </p>
                  <div className="max-h-[400px] overflow-y-auto border rounded-md p-4 space-y-3">
                    {catalogCategories.length === 0 ? (
                      <p className="text-center text-muted-foreground py-8">{t("common.loading")}</p>
                    ) : (
                      catalogCategories.map(([categoryId, category]: [string, any]) => (
                        <div key={categoryId} className="space-y-2">
                          <h4 className="font-medium text-sm">{category.name}</h4>
                          <div className="grid grid-cols-2 gap-2">
                            {category.lists.map((list: any) => (
                              <label
                                key={list.id}
                                className="flex items-center space-x-2 cursor-pointer p-2 rounded hover:bg-muted"
                              >
                                <Checkbox
                                  checked={selectedCatalogLists.includes(list.id)}
                                  onCheckedChange={() => handleCatalogListToggle(list.id)}
                                />
                                <span className="text-sm">{list.id}</span>
                                <Badge variant="secondary" className="ml-auto text-xs">
                                  {list.domain_count}
                                </Badge>
                              </label>
                            ))}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </TabsContent>
            </Tabs>

              <DialogFooter>
                <Button type="submit" disabled={addRule.isPending}>
                  {t("rules.addRule")}
                </Button>
              </DialogFooter>

          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
