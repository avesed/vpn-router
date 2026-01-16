import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useUpdateNodeChain } from "../../api/hooks/useChains";
import { usePeerNodes } from "../../api/hooks/usePeerNodes";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "../ui/form";
import { Input } from "../ui/input";
import { toast } from "sonner";
import { Checkbox } from "../ui/checkbox";
import { ScrollArea } from "../ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { useAllEgress } from "../../api/hooks/useEgress";
import type { NodeChain } from "../../types";
import { Loader2 } from "lucide-react";

const formSchema = z.object({
  name: z.string().min(1, "Name is required"),
  description: z.string().optional(),
  hops: z.array(z.string()).min(1, "At least one hop is required"),
  exit_egress: z.string().optional(),
  enabled: z.boolean().optional(),
});

type FormValues = z.infer<typeof formSchema>;

interface ChainEditDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  chain: NodeChain | null;
}

export function ChainEditDialog({ open, onOpenChange, chain }: ChainEditDialogProps) {
  const { t } = useTranslation();
  const updateChain = useUpdateNodeChain();
  const { data: peers } = usePeerNodes();
  const { data: allEgress } = useAllEgress();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: "",
      description: "",
      hops: [],
      exit_egress: "",
      enabled: true,
    },
  });

  // Reset form when dialog opens with chain data
  useEffect(() => {
    if (open && chain) {
      form.reset({
        name: chain.name,
        description: chain.description || "",
        hops: chain.hops || [],
        exit_egress: chain.exit_egress || "",
        enabled: chain.enabled,
      });
    }
  }, [open, chain, form]);

  const onSubmit = (values: FormValues) => {
    if (!chain) return;

    toast.promise(
      updateChain.mutateAsync({
        tag: chain.tag,
        data: values
      }),
      {
        loading: t("common.saving"),
        success: () => {
          onOpenChange(false);
          return t("chains.updateSuccess", { name: values.name });
        },
        error: () => t("chains.updateFailed"),
      }
    );
  };

  const availablePeers = peers?.nodes || [];
  
  // Build available egress options
  const egressOptions: { value: string; label: string }[] = [];
  if (allEgress) {
    allEgress.pia?.forEach(e => egressOptions.push({ value: e.tag, label: `${e.tag} (PIA)` }));
    allEgress.custom?.forEach(e => egressOptions.push({ value: e.tag, label: `${e.tag} (WireGuard)` }));
    allEgress.direct?.forEach(e => egressOptions.push({ value: e.tag, label: `${e.tag} (Direct)` }));
    allEgress.warp?.forEach(e => egressOptions.push({ value: e.tag, label: `${e.tag} (WARP)` }));
    allEgress.openvpn?.forEach(e => egressOptions.push({ value: e.tag, label: `${e.tag} (OpenVPN)` }));
    allEgress.v2ray?.forEach(e => egressOptions.push({ value: e.tag, label: `${e.tag} (V2Ray)` }));
  }

  if (!chain) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t("chains.editChain", { defaultValue: "Edit Chain" })}</DialogTitle>
          <DialogDescription>
            {t("chains.editDescription", { defaultValue: "Modify chain configuration" })} - {chain.tag}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t("chains.name")}</FormLabel>
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
                      <div className="text-sm text-muted-foreground p-2">{t("chains.noNodes")}</div>
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
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder={t("chains.exitEgressHint", { defaultValue: "Select exit egress (optional)" })} />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="">
                        {t("chains.noExitEgress", { defaultValue: "None (use terminal node's default)" })}
                      </SelectItem>
                      {egressOptions.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button variant="outline" type="button" onClick={() => onOpenChange(false)}>
                {t("common.cancel")}
              </Button>
              <Button type="submit" disabled={updateChain.isPending}>
                {updateChain.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("common.save")}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
