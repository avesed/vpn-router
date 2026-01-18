import { useState } from "react";
import { useTranslation } from "react-i18next";
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
import { useIngressConfig } from "@/api/hooks/useIngress";

const formSchema = z.object({
  code: z.string().min(1, "Pairing code is required"),
  local_node_description: z.string().optional(),
  local_endpoint: z.string().min(1, "Local endpoint is required"),
  api_port: z.coerce.number().optional(),
});

type FormValues = z.infer<typeof formSchema>;

export function ImportPairingDialog() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<{ 
    success: boolean; 
    message: string; 
    response_code: string | null;
    bidirectional: boolean | null;
  } | null>(null);

  const importPairRequest = useImportPairRequest();
  const { data: ingressData } = useIngressConfig();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any,
    defaultValues: {
      code: "",
      local_node_description: "",
      local_endpoint: window.location.hostname,
      api_port: 36000,
    },
  });

  const onSubmit = (data: FormValues) => {
    const nodeTag = ingressData?.local_node_tag;
    if (!nodeTag) {
      toast.error(t("pairing.nodeTagMissing"));
      return;
    }
    importPairRequest.mutate({
      ...data,
      local_node_tag: nodeTag,
    }, {
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

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(t("common.copied"));
    } catch {
      // Fallback for non-HTTPS environments
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.opacity = "0";
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      toast.success(t("common.copied"));
    }
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
        <Button variant="outline">{t("pairing.importButton")}</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>{t("pairing.importTitle")}</DialogTitle>
          <DialogDescription>{t("pairing.importDescription")}</DialogDescription>
        </DialogHeader>

        {!result ? (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="code"
                render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t("pairing.pairingCode")}</FormLabel>
                      <FormControl>
                        <Textarea 
                          placeholder={t("pairing.pairingCodePlaceholder")}
                          className="resize-none font-mono text-xs"
                          rows={4}
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>

                )}
              />

              <div className="rounded-md border p-3 bg-muted/50">
                <div className="text-sm text-muted-foreground">{t("pairing.localNodeTag")}</div>
                <div className="font-medium">
                  {ingressData?.local_node_tag || (
                    <span className="text-destructive">{t("pairing.nodeTagMissing")}</span>
                  )}
                </div>
              </div>

              <FormField
                control={form.control}
                name="local_endpoint"
                render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t("pairing.publicAddress")}</FormLabel>
                      <FormControl>
                        <Input placeholder={t("pairing.publicAddressPlaceholder")} {...field} />
                      </FormControl>
                      <FormDescription>{t("pairing.publicAddressHint")}</FormDescription>
                      <FormMessage />
                    </FormItem>

                )}
              />

              <Button 
                type="submit" 
                className="w-full" 
                disabled={importPairRequest.isPending || !ingressData?.local_node_tag}
              >
                {importPairRequest.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                {t("pairing.importConnectButton")}
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
                  {t("pairing.bidirectionalNotice")}
                </div>
                <label className="text-sm font-medium">{t("pairing.responseCode")}</label>
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
              {t("common.close")}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
