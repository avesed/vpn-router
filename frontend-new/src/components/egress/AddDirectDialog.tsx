import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useCreateDirectEgress } from "../../api/hooks/useEgress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "../ui/form";
import { Input } from "../ui/input";
import { toast } from "sonner";

const formSchema = z.object({
  tag: z.string().min(1, "Tag is required"),
  description: z.string().optional(),
  bind_interface: z.string().optional(),
  inet4_bind_address: z.string().optional(),
  inet6_bind_address: z.string().optional(),
});

interface AddDirectDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AddDirectDialog({ open, onOpenChange }: AddDirectDialogProps) {
  const createEgress = useCreateDirectEgress();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      tag: "",
      description: "",
      bind_interface: "",
      inet4_bind_address: "",
      inet6_bind_address: "",
    },
  });

  const onSubmit = (values: z.infer<typeof formSchema>) => {
    toast.promise(
      createEgress.mutateAsync(values),
      {
        loading: "Creating Direct egress...",
        success: () => {
          onOpenChange(false);
          form.reset();
          return "Direct egress created successfully";
        },
        error: (err) => `Failed to create egress: ${err.message}`,
      }
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Direct Egress</DialogTitle>
          <DialogDescription>
            Create a direct connection bound to a specific network interface or IP address.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="tag"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Tag (Name)</FormLabel>
                  <FormControl>
                    <Input placeholder="direct-eth0" {...field} />
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
              name="bind_interface"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Bind Interface (Optional)</FormLabel>
                  <FormControl>
                    <Input placeholder="eth0" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="inet4_bind_address"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Bind IPv4 Address (Optional)</FormLabel>
                  <FormControl>
                    <Input placeholder="192.168.1.100" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button type="submit" disabled={createEgress.isPending}>
                Create Egress
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
