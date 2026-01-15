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
  const { t } = useTranslation();
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
    toast.success(t("common.copied"));
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
              <FormField
                control={form.control}
                name="node_tag"
                render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t("peers.tag")}</FormLabel>
                      <FormControl>
                        <Input placeholder={t("peers.tagPlaceholder")} {...field} />
                      </FormControl>
                      <FormDescription>{t("peers.tagHint")}</FormDescription>
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
                      <FormLabel>{t("peers.endpoint")}</FormLabel>
                      <FormControl>
                        <Input placeholder={t("peers.endpointPlaceholder")} {...field} />
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
                      <FormLabel>{t("pairing.bidirectionalTitle")}</FormLabel>
                      <FormDescription>{t("pairing.bidirectionalDescription")}</FormDescription>
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
                {t("pairing.generateCode")}
              </Button>
            </form>
          </Form>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">{t("pairing.pairingCode")}</label>
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
              <label className="text-sm font-medium">{t("pairing.pskLabel")}</label>
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
              {t("pairing.generateAnother")}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
