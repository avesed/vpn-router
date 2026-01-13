import { useState, useEffect } from "react";
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
      toast.success("Configuration copied to clipboard");
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
          <DialogTitle>Client Configuration: {clientName}</DialogTitle>
          <DialogDescription>
            Scan the QR code or copy the configuration file.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="qrcode" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="qrcode">QR Code</TabsTrigger>
            <TabsTrigger value="config">Config File</TabsTrigger>
          </TabsList>
          
          <TabsContent value="qrcode" className="flex flex-col items-center justify-center p-4">
            {isLoadingQr ? (
              <Loader2 className="h-32 w-32 animate-spin text-muted-foreground" />
            ) : qrCodeUrl ? (
              <img src={qrCodeUrl} alt="WireGuard QR Code" className="h-64 w-64 border rounded-lg" />
            ) : (
              <p className="text-muted-foreground">Failed to load QR code</p>
            )}
            <p className="text-sm text-muted-foreground mt-4 text-center">
              Scan this code with the WireGuard mobile app
            </p>
            {!privateKey && (
              <Alert variant="destructive" className="mt-4">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  Private key is not available. If you see "YOUR_PRIVATE_KEY" in the config, 
                  you need to use the private key saved when this client was created.
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
                <pre className="p-4 rounded-lg bg-muted overflow-x-auto text-xs font-mono h-64 border">
                  {configText || "Failed to load configuration"}
                </pre>
              )}
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={handleCopyConfig} disabled={!configText}>
                <Copy className="mr-2 h-4 w-4" />
                Copy
              </Button>
              <Button variant="outline" size="sm" onClick={handleDownloadConfig} disabled={!configText}>
                <Download className="mr-2 h-4 w-4" />
                Download
              </Button>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
