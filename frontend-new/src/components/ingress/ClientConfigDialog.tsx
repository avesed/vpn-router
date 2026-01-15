import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useGetClientConfig, useGetClientQrCode } from "@/api/hooks/useIngress";
import { Loader2, Copy, Download, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

interface ClientConfigDialogProps {
  clientName: string | null;
  privateKey?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ClientConfigDialog({ clientName, privateKey, open, onOpenChange }: ClientConfigDialogProps) {
  const { t } = useTranslation();
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);
  const [configText, setConfigText] = useState<string | null>(null);
  const { mutate: getQrCode, isPending: isLoadingQr } = useGetClientQrCode();
  const { mutate: getConfig, isPending: isLoadingConfig } = useGetClientConfig();

  useEffect(() => {
    if (open && clientName) {
      setQrCodeUrl(null);
      setConfigText(null);
      
      getQrCode(
        { name: clientName, privateKey },
        {
          onSuccess: (url) => setQrCodeUrl(url),
        }
      );
      
      getConfig(
        { name: clientName, privateKey },
        {
          onSuccess: (text) => setConfigText(text),
        }
      );
    }
    
    return () => {
      if (qrCodeUrl) {
        URL.revokeObjectURL(qrCodeUrl);
      }
    };
  }, [open, clientName, privateKey, getQrCode, getConfig]);

  const handleCopyConfig = () => {
    if (configText) {
      navigator.clipboard.writeText(configText);
      toast.success(t("ingress.copied"));
    }
  };

  const handleDownloadConfig = () => {
    if (configText && clientName) {
      const blob = new Blob([configText], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${clientName}.conf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>{t("ingress.clientConfig")}: {clientName}</DialogTitle>
          <DialogDescription>
            {t("ingress.qrCodeHint")}
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="qrcode" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="qrcode">{t("common.qrCode")}</TabsTrigger>
            <TabsTrigger value="config">{t("common.configFile")}</TabsTrigger>
          </TabsList>

          <TabsContent value="qrcode" className="flex flex-col items-center justify-center p-4">
            {isLoadingQr ? (
              <Loader2 className="h-32 w-32 animate-spin text-muted-foreground" />
            ) : qrCodeUrl ? (
              <img src={qrCodeUrl} alt={t("ingress.qrCodeAlt")} className="h-64 w-64 border rounded-lg" />
            ) : (
              <p className="text-muted-foreground">{t("common.loadFailed")}</p>
            )}
            <p className="text-sm text-muted-foreground mt-4 text-center">
              {t("ingress.scanQrCode")}
            </p>
            {!privateKey && (
              <Alert variant="destructive" className="mt-4">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  {t("ingress.privateKeyHint")}
                </AlertDescription>
              </Alert>
            )}
          </TabsContent>

          <TabsContent value="config" className="space-y-4">
            <div className="relative">
              {isLoadingConfig ? (
                <div className="flex justify-center p-8">
                  <Loader2 className="h-8 w-8 animate-spin" />
                </div>
              ) : (
                <pre className="p-4 rounded-lg bg-muted overflow-auto text-xs font-mono h-64 border whitespace-pre-wrap break-words">
                  {configText || t("common.loadFailed")}
                </pre>
              )}
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={handleCopyConfig} disabled={!configText}>
                <Copy className="mr-2 h-4 w-4" />
                {t("common.copy")}
              </Button>
              <Button variant="outline" size="sm" onClick={handleDownloadConfig} disabled={!configText}>
                <Download className="mr-2 h-4 w-4" />
                {t("common.download")}
              </Button>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
