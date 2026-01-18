import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useCreateNodeChain } from "../../api/hooks/useChains";
import { usePeerNodes } from "../../api/hooks/usePeerNodes";
import { api } from "../../api/client";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "../ui/form";
import { Input } from "../ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { toast } from "sonner";
import { Checkbox } from "../ui/checkbox";
import { ScrollArea } from "../ui/scroll-area";
import { Loader2 } from "lucide-react";

const formSchema = z.object({
  tag: z.string().min(1, "Tag is required").regex(/^[a-z][a-z0-9-]*$/, "Must start with lowercase letter, only lowercase letters, numbers and hyphens"),
  name: z.string().optional(),  // Phase 11-Fix.B: 名称可选，默认使用 tag
  description: z.string().optional(),
  hops: z.array(z.string()).min(1, "At least 1 hop required"),
  exit_egress: z.string().optional(),
});

interface ChainCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface EgressOption {
  tag: string;
  name: string;
  type: string;
  enabled: boolean;
  description?: string;
}

export function ChainCreateDialog({ open, onOpenChange }: ChainCreateDialogProps) {
  const { t } = useTranslation();
  const createChain = useCreateNodeChain();
  const { data: peers } = usePeerNodes();
  const [terminalEgressOptions, setTerminalEgressOptions] = useState<EgressOption[]>([]);
  const [loadingEgress, setLoadingEgress] = useState(false);
  const [egressError, setEgressError] = useState<string | null>(null);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      tag: "",
      name: "",
      description: "",
      hops: [],
      exit_egress: "",
    },
  });

  const selectedHops = form.watch("hops");
  const lastHop = selectedHops.length > 0 ? selectedHops[selectedHops.length - 1] : null;

  // Fetch egress options from the last hop node when it changes
  useEffect(() => {
    if (!lastHop) {
      setTerminalEgressOptions([]);
      setEgressError(null);
      return;
    }

    const fetchEgress = async () => {
      setLoadingEgress(true);
      setEgressError(null);
      setTerminalEgressOptions([]);
      
      try {
        const response = await api.getPeerEgress(lastHop);
        setTerminalEgressOptions(response.egress.filter(e => e.enabled));
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : "Failed to fetch egress options";
        setEgressError(message);
        console.error("Failed to fetch terminal egress:", error);
      } finally {
        setLoadingEgress(false);
      }
    };

    fetchEgress();
  }, [lastHop]);

  // Reset exit_egress when hops change
  useEffect(() => {
    form.setValue("exit_egress", "");
  }, [lastHop, form]);

  const onSubmit = (values: z.infer<typeof formSchema>) => {
    toast.promise(
      createChain.mutateAsync(values),
      {
        loading: t("common.creating"),
        success: () => {
          onOpenChange(false);
          form.reset();
          setTerminalEgressOptions([]);
          return t("chains.createSuccess", { name: values.name || values.tag });
        },
        error: () => t("chains.createFailed"),
      }
    );
  };

  const availablePeers = peers?.nodes?.filter(p => p.tunnel_status === "connected" && p.enabled) || [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t("chains.addChain")}</DialogTitle>
          <DialogDescription>{t("chains.createDescription")}</DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="tag"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t("chains.tag")}</FormLabel>
                  <FormControl>
                    <Input placeholder={t("chains.tagPlaceholder")} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t("chains.name")} <span className="text-muted-foreground text-xs">({t("common.optional")})</span></FormLabel>
                  <FormControl>
                    <Input placeholder={t("chains.namePlaceholder")} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t("chains.description")}</FormLabel>
                  <FormControl>
                    <Input placeholder={t("chains.descriptionPlaceholder")} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="hops"
              render={() => (
                <FormItem>
                    <div className="mb-4">
                      <FormLabel className="text-base">{t("chains.hops")}</FormLabel>
                      <DialogDescription>{t("chains.hopsHint")}</DialogDescription>
                    </div>

                  <ScrollArea className="h-40 border rounded-md p-2">
                    {availablePeers.length === 0 ? (
                      <div className="text-sm text-muted-foreground p-2">{t("chains.noConnectedNodes")}</div>
                    ) : (
                      availablePeers.map((peer) => (
                        <FormField
                          key={peer.tag}
                          control={form.control}
                          name="hops"
                          render={({ field }) => {
                            return (
                              <FormItem
                                key={peer.tag}
                                className="flex flex-row items-start space-x-3 space-y-0 p-2 hover:bg-muted/50 rounded"
                              >
                                <FormControl>
                                  <Checkbox
                                    checked={field.value?.includes(peer.tag)}
                                    onCheckedChange={(checked) => {
                                      return checked
                                        ? field.onChange([...field.value, peer.tag])
                                        : field.onChange(
                                            field.value?.filter(
                                              (value) => value !== peer.tag
                                            )
                                          )
                                    }}
                                  />
                                </FormControl>
                                <FormLabel className="font-normal cursor-pointer w-full">
                                  {peer.name} ({peer.tag})
                                </FormLabel>
                              </FormItem>
                            )
                          }}
                        />
                      ))
                    )}
                  </ScrollArea>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="exit_egress"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t("chains.exitEgress")}</FormLabel>
                  {lastHop ? (
                    <>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger disabled={loadingEgress}>
                            {loadingEgress ? (
                              <div className="flex items-center gap-2">
                                <Loader2 className="h-4 w-4 animate-spin" />
                                <span>{t("common.loading")}</span>
                              </div>
                            ) : (
                              <SelectValue placeholder={t("chains.selectExitEgress")} />
                            )}
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {terminalEgressOptions.map((egress) => (
                            <SelectItem key={egress.tag} value={egress.tag}>
                              {egress.name} ({egress.type})
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {egressError && (
                        <p className="text-sm text-destructive">{egressError}</p>
                      )}
                      <p className="text-xs text-muted-foreground">
                        {t("chains.exitEgressFromNode", { node: lastHop })}
                      </p>
                    </>
                  ) : (
                    <p className="text-sm text-muted-foreground">{t("chains.selectHopsFirst")}</p>
                  )}
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button type="submit" disabled={createChain.isPending}>
                {t("chains.addChain")}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
