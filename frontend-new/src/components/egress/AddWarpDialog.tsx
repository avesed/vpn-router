import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useRegisterWarpEgress } from "../../api/hooks/useEgress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "../ui/form";
import { Input } from "../ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { toast } from "sonner";

const formSchema = z.object({
  tag: z.string().min(1, "Tag is required"),
  description: z.string().optional(),
  license_key: z.string().optional(),
  protocol: z.enum(["masque", "wireguard"]),
});

type FormValues = z.infer<typeof formSchema>;

interface AddWarpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AddWarpDialog({ open, onOpenChange }: AddWarpDialogProps) {
  const registerWarp = useRegisterWarpEgress();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any,
    defaultValues: {
      tag: "warp-1",
      description: "",
      license_key: "",
      protocol: "masque",
    },
  });

  const onSubmit = (values: FormValues) => {
    toast.promise(
      registerWarp.mutateAsync(values),
      {
        loading: "Registering WARP account...",
        success: () => {
          onOpenChange(false);
          form.reset();
          return "WARP egress registered successfully";
        },
        error: (err) => `Failed to register WARP: ${err.message}`,
      }
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Register WARP Egress</DialogTitle>
          <DialogDescription>
            Register a new Cloudflare WARP account.
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
                    <Input placeholder="warp-1" {...field} />
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
              name="license_key"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>License Key (Optional)</FormLabel>
                  <FormControl>
                    <Input placeholder="Leave empty for free account" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="protocol"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Protocol</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select protocol" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="masque">MASQUE (Recommended)</SelectItem>
                      <SelectItem value="wireguard">WireGuard</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter>
              <Button type="submit" disabled={registerWarp.isPending}>
                Register WARP
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
