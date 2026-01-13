import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Copy, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { useGeneratePairRequest } from "@/api/hooks/usePairing";

const formSchema = z.object({
  node_tag: z.string().min(1, "Node tag is required"),
  node_description: z.string().optional(),
  endpoint: z.string().min(1, "Endpoint is required"),
  tunnel_type: z.enum(["wireguard", "xray"]),
  bidirectional: z.boolean().optional(),
  api_port: z.coerce.number().optional(),
});

type FormValues = z.infer<typeof formSchema>;

export function GeneratePairingDialog() {
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<{ code: string; psk: string } | null>(null);
  
  const generatePairRequest = useGeneratePairRequest();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any,
    defaultValues: {
      node_tag: "",
      node_description: "",
      endpoint: window.location.hostname,
      tunnel_type: "wireguard",
      bidirectional: false,
      api_port: 36000,
    },
  });

  const onSubmit = (data: FormValues) => {
    generatePairRequest.mutate({
      ...data,
      bidirectional: data.bidirectional ?? false,
    }, {
      onSuccess: (response) => {
        setResult({ code: response.code, psk: response.psk });
      },
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  const reset = () => {
    setResult(null);
    form.reset();
  };

  return (
    <Dialog open={open} onOpenChange={(val) => {
      setOpen(val);
      if (!val) reset();
    }}>
      <DialogTrigger asChild>
        <Button>Generate Pairing Code</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Generate Pairing Code</DialogTitle>
          <DialogDescription>
            Generate a code to pair with another node. Share this code securely.
          </DialogDescription>
        </DialogHeader>

        {!result ? (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="node_tag"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Node Tag</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g. home-router" {...field} />
                    </FormControl>
                    <FormDescription>
                      Unique identifier for this node
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="endpoint"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Endpoint</FormLabel>
                      <FormControl>
                        <Input placeholder="e.g. 1.2.3.4" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="tunnel_type"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Tunnel Type</FormLabel>
                      <Select 
                        onValueChange={field.onChange} 
                        defaultValue={field.value}
                      >
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select tunnel type" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="wireguard">WireGuard</SelectItem>
                          <SelectItem value="xray">Xray (VLESS)</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={form.control}
                name="bidirectional"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md border p-4">
                    <FormControl>
                      <Checkbox
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                    <div className="space-y-1 leading-none">
                      <FormLabel>
                        Bidirectional Connection
                      </FormLabel>
                      <FormDescription>
                        Allow the other node to connect back to this node
                      </FormDescription>
                    </div>
                  </FormItem>
                )}
              />

              <Button 
                type="submit" 
                className="w-full" 
                disabled={generatePairRequest.isPending}
              >
                {generatePairRequest.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Generate Code
              </Button>
            </form>
          </Form>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Pairing Code</label>
              <div className="flex items-center space-x-2">
                <code className="flex-1 rounded bg-muted p-2 font-mono text-sm break-all">
                  {result.code}
                </code>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => copyToClipboard(result.code)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Pre-shared Key (PSK)</label>
              <div className="flex items-center space-x-2">
                <code className="flex-1 rounded bg-muted p-2 font-mono text-sm break-all">
                  {result.psk}
                </code>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => copyToClipboard(result.psk)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <Button variant="outline" className="w-full" onClick={reset}>
              Generate Another
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
