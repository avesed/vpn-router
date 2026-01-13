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
import { Textarea } from "@/components/ui/textarea";
import { useImportPairRequest } from "@/api/hooks/usePairing";

const formSchema = z.object({
  code: z.string().min(1, "Pairing code is required"),
  local_node_tag: z.string().min(1, "Local node tag is required"),
  local_node_description: z.string().optional(),
  local_endpoint: z.string().min(1, "Local endpoint is required"),
  api_port: z.coerce.number().optional(),
});

type FormValues = z.infer<typeof formSchema>;

export function ImportPairingDialog() {
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<{ 
    success: boolean; 
    message: string; 
    response_code: string | null;
    bidirectional: boolean | null;
  } | null>(null);
  
  const importPairRequest = useImportPairRequest();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any,
    defaultValues: {
      code: "",
      local_node_tag: "",
      local_node_description: "",
      local_endpoint: window.location.hostname,
      api_port: 36000,
    },
  });

  const onSubmit = (data: FormValues) => {
    importPairRequest.mutate(data, {
      onSuccess: (response) => {
        setResult({ 
          success: response.success, 
          message: response.message,
          response_code: response.response_code,
          bidirectional: response.bidirectional
        });
        toast.success(response.message);
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
        <Button variant="outline">Import Pairing Code</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Import Pairing Code</DialogTitle>
          <DialogDescription>
            Enter a pairing code from another node to establish a connection.
          </DialogDescription>
        </DialogHeader>

        {!result ? (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="code"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Pairing Code</FormLabel>
                    <FormControl>
                      <Textarea 
                        placeholder="Paste the pairing code here..." 
                        className="resize-none font-mono text-xs"
                        rows={4}
                        {...field} 
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="local_node_tag"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Local Node Tag</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g. office-router" {...field} />
                    </FormControl>
                    <FormDescription>
                      Identifier for this node on the remote peer
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="local_endpoint"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Local Endpoint</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g. 1.2.3.4" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button 
                type="submit" 
                className="w-full" 
                disabled={importPairRequest.isPending}
              >
                {importPairRequest.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Import & Connect
              </Button>
            </form>
          </Form>
        ) : (
          <div className="space-y-4">
            <div className="rounded-md bg-green-50 p-4 text-sm text-green-700 dark:bg-green-900/20 dark:text-green-400">
              {result.message}
            </div>

            {result.bidirectional && result.response_code && (
              <div className="space-y-2">
                <div className="rounded-md bg-blue-50 p-3 text-sm text-blue-700 dark:bg-blue-900/20 dark:text-blue-400">
                  This is a bidirectional connection. Please share the response code below with the other peer to complete the setup.
                </div>
                <label className="text-sm font-medium">Response Code</label>
                <div className="flex items-center space-x-2">
                  <code className="flex-1 rounded bg-muted p-2 font-mono text-sm break-all">
                    {result.response_code}
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => copyToClipboard(result.response_code!)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}

            <Button variant="outline" className="w-full" onClick={() => setOpen(false)}>
              Close
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
