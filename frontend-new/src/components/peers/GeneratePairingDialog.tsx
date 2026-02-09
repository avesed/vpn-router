import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Copy, Loader2, CheckCircle } from "lucide-react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { useGeneratePairRequest, useCompletePairing } from "@/api/hooks/usePairing";
import { useIngressConfig } from "@/api/hooks/useIngress";

const formSchema = z.object({
  node_description: z.string().optional(),
  endpoint: z.string().min(1, "Endpoint is required"),
  tunnel_type: z.enum(["wireguard", "xray"]),
  bidirectional: z.boolean().optional(),
  api_port: z.coerce.number().optional(),
});

type FormValues = z.infer<typeof formSchema>;

export function GeneratePairingDialog() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<{ code: string } | null>(null);
  const [responseCode, setResponseCode] = useState("");
  const [completeResult, setCompleteResult] = useState<{
    success: boolean;
    message: string;
    created_node_tag: string | null;
  } | null>(null);

  const generatePairRequest = useGeneratePairRequest();
  const completePairing = useCompletePairing();
  const { data: ingressConfig, isLoading: isLoadingIngress } = useIngressConfig();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any,
    defaultValues: {
      node_description: "",
      endpoint: window.location.hostname,
      tunnel_type: "wireguard",
      bidirectional: false,
      api_port: 36000,
    },
  });

  const onSubmit = (data: FormValues) => {
    const nodeTag = ingressConfig?.local_node_tag;
    if (!nodeTag) {
      toast.error(t("pairing.nodeTagMissing"));
      return;
    }
    generatePairRequest.mutate({
      ...data,
      node_tag: nodeTag,
      bidirectional: data.bidirectional ?? false,
    }, {
      onSuccess: (response) => {
        setResult({ code: response.code });
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
    setResponseCode("");
    setCompleteResult(null);
    form.reset();
  };

  const handleCompletePairing = () => {
    if (!responseCode.trim()) {
      toast.error(t("pairing.responseCodeRequired"));
      return;
    }
    completePairing.mutate({
      code: responseCode.trim(),
      pending_request: {},
    }, {
      onSuccess: (response) => {
        setCompleteResult({
          success: response.success,
          message: response.message,
          created_node_tag: response.created_node_tag,
        });
        if (response.success) {
          toast.success(response.message);
        }
      },
    });
  };

  return (
    <Dialog open={open} onOpenChange={(val) => {
      setOpen(val);
      if (!val) reset();
    }}>
      <DialogTrigger asChild>
        <Button>{t("pairing.generateButton")}</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>{t("pairing.generateTitle")}</DialogTitle>
          <DialogDescription>{t("pairing.generateDescription")}</DialogDescription>
        </DialogHeader>

        {!result ? (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <div className="rounded-md border p-3 bg-muted/50">
                <div className="text-sm text-muted-foreground">{t("peers.tag")}</div>
                <div className="font-medium">
                  {isLoadingIngress ? (
                    <span className="text-muted-foreground">{t("common.loading")}</span>
                  ) : ingressConfig?.local_node_tag || (
                    <span className="text-destructive">{t("pairing.nodeTagMissing")}</span>
                  )}
                </div>
              </div>

              <FormField
                control={form.control}
                name="endpoint"
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

              <FormField
                control={form.control}
                name="tunnel_type"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t("peers.tunnelType")}</FormLabel>
                    <Select 
                      onValueChange={field.onChange} 
                      defaultValue={field.value}
                    >
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue
                            placeholder={t("common.selectPlaceholder", { item: t("peers.tunnelType") })}
                          />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="wireguard">{t("peers.wireguard")}</SelectItem>
                        <SelectItem value="xray">{t("pairing.tunnelTypeXray")}</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

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
                      <FormLabel>{t("pairing.bidirectionalTitle")}</FormLabel>
                      <FormDescription>{t("pairing.bidirectionalDescription")}</FormDescription>
                    </div>
                  </FormItem>
                )}
              />

              <Button 
                type="submit" 
                className="w-full" 
                disabled={generatePairRequest.isPending || isLoadingIngress || !ingressConfig?.local_node_tag}
              >
                {(generatePairRequest.isPending || isLoadingIngress) && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                {t("pairing.generateCode")}
              </Button>
            </form>
          </Form>
        ) : (
          <div className="space-y-4">
            {!completeResult ? (
              <>
                <div className="space-y-2">
                  <label className="text-sm font-medium">{t("pairing.pairingCode")}</label>
                  <div className="flex items-center space-x-2">
                    <code className="flex-1 rounded bg-muted p-2 font-mono text-sm break-all max-h-32 overflow-y-auto">
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

                <div className="border-t pt-4 space-y-3">
                  <div className="text-sm text-muted-foreground">
                    {t("pairing.completeHint")}
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">{t("pairing.responseCode")}</label>
                    <Textarea
                      placeholder={t("pairing.responseCodePlaceholder")}
                      className="resize-none font-mono text-xs"
                      rows={3}
                      value={responseCode}
                      onChange={(e) => setResponseCode(e.target.value)}
                    />
                  </div>
                  <Button
                    className="w-full"
                    onClick={handleCompletePairing}
                    disabled={completePairing.isPending || !responseCode.trim()}
                  >
                    {completePairing.isPending && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    {t("pairing.completeSubmit")}
                  </Button>
                </div>

                <Button variant="outline" className="w-full" onClick={reset}>
                  {t("pairing.generateAnother")}
                </Button>
              </>
            ) : (
              <>
                {completeResult.success ? (
                  <div className="rounded-md bg-green-50 p-4 dark:bg-green-900/20">
                    <div className="flex items-center gap-3">
                      <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
                      <div>
                        <p className="text-sm font-medium text-green-700 dark:text-green-400">
                          {completeResult.message}
                        </p>
                        {completeResult.created_node_tag && (
                          <p className="text-sm text-green-600 dark:text-green-500 mt-1">
                            {t("pairing.createdNode")}: {completeResult.created_node_tag}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-md bg-red-50 p-4 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-400">
                    {completeResult.message}
                  </div>
                )}

                <Button variant="outline" className="w-full" onClick={() => setOpen(false)}>
                  {t("common.close")}
                </Button>
              </>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
