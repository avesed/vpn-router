import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useCreateNodeChain } from "../../api/hooks/useChains";
import { usePeerNodes } from "../../api/hooks/usePeerNodes";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "../ui/form";
import { Input } from "../ui/input";
import { toast } from "sonner";
import { Checkbox } from "../ui/checkbox";
import { ScrollArea } from "../ui/scroll-area";

const formSchema = z.object({
  tag: z.string().min(1, "Tag is required").regex(/^[a-z][a-z0-9-]*$/, "Must start with lowercase letter, only lowercase letters, numbers and hyphens"),
  name: z.string().min(1, "Name is required"),
  description: z.string().optional(),
  hops: z.array(z.string()).min(2, "At least 2 hops required for multi-hop chain"),
  exit_egress: z.string().optional(),
});

interface ChainCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ChainCreateDialog({ open, onOpenChange }: ChainCreateDialogProps) {
  const { t } = useTranslation();
  const createChain = useCreateNodeChain();
  const { data: peers } = usePeerNodes();

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

  const onSubmit = (values: z.infer<typeof formSchema>) => {
    toast.promise(
      createChain.mutateAsync(values),
      {
        loading: t("common.creating"),
        success: () => {
          onOpenChange(false);
          form.reset();
          return t("chains.createSuccess", { name: values.name || values.tag });
        },
        error: () => t("chains.createFailed"),
      }
    );
  };

  const availablePeers = peers?.nodes || [];

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
                  <FormControl>
                    <Input placeholder={t("chains.exitEgressHint")} {...field} />
                  </FormControl>
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
