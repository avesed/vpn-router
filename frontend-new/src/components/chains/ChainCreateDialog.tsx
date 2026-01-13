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
  tag: z.string().min(1, "Tag is required"),
  name: z.string().min(1, "Name is required"),
  description: z.string().optional(),
  hops: z.array(z.string()).min(1, "At least one hop is required"),
  exit_egress: z.string().optional(),
});

interface ChainCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ChainCreateDialog({ open, onOpenChange }: ChainCreateDialogProps) {
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
        loading: "Creating chain...",
        success: () => {
          onOpenChange(false);
          form.reset();
          return "Chain created successfully";
        },
        error: (err) => `Failed to create chain: ${err.message}`,
      }
    );
  };

  const availablePeers = peers?.nodes || [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create Node Chain</DialogTitle>
          <DialogDescription>
            Create a multi-hop chain through peer nodes.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="tag"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Tag</FormLabel>
                  <FormControl>
                    <Input placeholder="chain-1" {...field} />
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
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input placeholder="My Chain" {...field} />
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
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Input placeholder="Optional description" {...field} />
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
                    <FormLabel className="text-base">Select Hops (Ordered)</FormLabel>
                    <DialogDescription>
                      Select peer nodes in the order they should be traversed.
                    </DialogDescription>
                  </div>
                  <ScrollArea className="h-40 border rounded-md p-2">
                    {availablePeers.length === 0 ? (
                      <div className="text-sm text-muted-foreground p-2">No peer nodes available.</div>
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
                  <FormLabel>Exit Egress (Optional)</FormLabel>
                  <FormControl>
                    <Input placeholder="Tag of egress on the last node" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button type="submit" disabled={createChain.isPending}>
                Create Chain
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
