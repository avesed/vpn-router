import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useCreateCustomEgress, useParseWireGuardConf } from "../../api/hooks/useEgress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "../ui/form";
import { Input } from "../ui/input";
import { Textarea } from "../ui/textarea";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";

const formSchema = z.object({
  tag: z.string().min(1, "Tag is required"),
  description: z.string().optional(),
  server: z.string().min(1, "Server is required"),
  port: z.coerce.number().min(1, "Port is required"),
  private_key: z.string().min(1, "Private key is required"),
  public_key: z.string().min(1, "Public key is required"),
  address: z.string().min(1, "Address is required"),
  mtu: z.coerce.number().optional(),
  dns: z.string().optional(),
  pre_shared_key: z.string().optional(),
});

type FormValues = z.infer<typeof formSchema>;

interface AddWireGuardDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AddWireGuardDialog({ open, onOpenChange }: AddWireGuardDialogProps) {
  const [activeTab, setActiveTab] = useState("paste");
  const [configContent, setConfigContent] = useState("");
  
  const createEgress = useCreateCustomEgress();
  const parseConf = useParseWireGuardConf();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any,
    defaultValues: {
      tag: "",
      description: "",
      server: "",
      port: 51820,
      private_key: "",
      public_key: "",
      address: "",
      mtu: 1420,
      dns: "1.1.1.1",
      pre_shared_key: "",
    },
  });

  const handleParse = async () => {
    if (!configContent) {
      toast.error("Please paste configuration content");
      return;
    }

    try {
      const result = await parseConf.mutateAsync(configContent);
      form.setValue("server", result.server);
      form.setValue("port", result.port);
      form.setValue("private_key", result.private_key);
      form.setValue("public_key", result.public_key);
      form.setValue("address", result.address);
      if (result.mtu) form.setValue("mtu", result.mtu);
      if (result.dns) form.setValue("dns", result.dns);
      if (result.pre_shared_key) form.setValue("pre_shared_key", result.pre_shared_key);
      
      setActiveTab("manual");
      toast.success("Configuration parsed successfully");
    } catch (err: any) {
      toast.error(`Failed to parse config: ${err.message}`);
    }
  };

  const onSubmit = (values: FormValues) => {
    toast.promise(
      createEgress.mutateAsync(values),
      {
        loading: "Creating WireGuard egress...",
        success: () => {
          onOpenChange(false);
          form.reset();
          setConfigContent("");
          setActiveTab("paste");
          return "WireGuard egress created successfully";
        },
        error: (err) => `Failed to create egress: ${err.message}`,
      }
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add WireGuard Egress</DialogTitle>
          <DialogDescription>
            Add a new WireGuard connection by pasting a config file or entering details manually.
          </DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="paste">Paste Config</TabsTrigger>
            <TabsTrigger value="manual">Manual Entry</TabsTrigger>
          </TabsList>

          <TabsContent value="paste" className="space-y-4 py-4">
            <Textarea
              placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = ...&#10;DNS = ...&#10;&#10;[Peer]&#10;PublicKey = ...&#10;Endpoint = ...&#10;AllowedIPs = ..."
              className="h-64 font-mono text-sm"
              value={configContent}
              onChange={(e) => setConfigContent(e.target.value)}
            />
            <Button onClick={handleParse} disabled={parseConf.isPending} className="w-full">
              Parse Configuration
            </Button>
          </TabsContent>

          <TabsContent value="manual" className="space-y-4 py-4">
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
                          <Input placeholder="wg-provider" {...field} />
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
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="server"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Server Address</FormLabel>
                        <FormControl>
                          <Input placeholder="vpn.example.com" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="port"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Port</FormLabel>
                        <FormControl>
                          <Input type="number" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <FormField
                  control={form.control}
                  name="private_key"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Private Key</FormLabel>
                      <FormControl>
                        <Input type="password" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="public_key"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Peer Public Key</FormLabel>
                      <FormControl>
                        <Input {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="grid grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="address"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Interface Address (CIDR)</FormLabel>
                        <FormControl>
                          <Input placeholder="10.2.0.2/32" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="dns"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>DNS</FormLabel>
                        <FormControl>
                          <Input placeholder="1.1.1.1" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <FormField
                  control={form.control}
                  name="pre_shared_key"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Pre-Shared Key (Optional)</FormLabel>
                      <FormControl>
                        <Input type="password" {...field} />
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
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
