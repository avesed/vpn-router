import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useAddCustomRule } from "../../api/hooks/useRules";
import { useAllEgress } from "../../api/hooks/useEgress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "../ui/form";
import { Input } from "../ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Textarea } from "../ui/textarea";
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
  const addRule = useAddCustomRule();
  const { data: allEgress } = useAllEgress();

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
    const domains = values.domains ? values.domains.split("\n").filter(Boolean) : undefined;
    const domainKeywords = values.domainKeywords ? values.domainKeywords.split("\n").filter(Boolean) : undefined;
    const ipCidrs = values.ipCidrs ? values.ipCidrs.split("\n").filter(Boolean) : undefined;

    toast.promise(
      addRule.mutateAsync({
        tag: values.tag,
        outbound: values.outbound,
        domains,
        domainKeywords,
        ipCidrs,
      }),
      {
        loading: "Adding rule...",
        success: () => {
          onOpenChange(false);
          form.reset();
          return "Rule added successfully";
        },
        error: (err) => `Failed to add rule: ${err.message}`,
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Add Custom Rule</DialogTitle>
          <DialogDescription>
            Create a new routing rule based on domains, keywords, or IPs.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="tag"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Tag (Name)</FormLabel>
                    <FormControl>
                      <Input placeholder="my-rule" {...field} />
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
                    <FormLabel>Target Outbound</FormLabel>
                    <Select onValueChange={field.onChange} defaultValue={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Select outbound" />
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

            <FormField
              control={form.control}
              name="domains"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Domains (One per line)</FormLabel>
                  <FormControl>
                    <Textarea placeholder="example.com&#10;google.com" className="h-20" {...field} />
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
                  <FormLabel>Domain Keywords (One per line)</FormLabel>
                  <FormControl>
                    <Textarea placeholder="google&#10;facebook" className="h-20" {...field} />
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
                  <FormLabel>IP CIDRs (One per line)</FormLabel>
                  <FormControl>
                    <Textarea placeholder="1.1.1.1/32&#10;8.8.8.8/32" className="h-20" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button type="submit" disabled={addRule.isPending}>
                Create Rule
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
