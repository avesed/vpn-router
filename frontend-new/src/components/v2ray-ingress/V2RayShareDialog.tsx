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
import type { V2RayUser } from "@/types";
import { useGetV2RayUserUri, useGetV2RayUserQrCode } from "@/api/hooks/useV2RayIngress";
import { Loader2, Copy } from "lucide-react";
import { toast } from "sonner";

interface V2RayShareDialogProps {
  user: V2RayUser | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function V2RayShareDialog({ user, open, onOpenChange }: V2RayShareDialogProps) {
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);
  const [shareUri, setShareUri] = useState<string | null>(null);
  const [qrError, setQrError] = useState<string | null>(null);
  const [uriError, setUriError] = useState<string | null>(null);
  const { mutate: getQrCode, isPending: isLoadingQr } = useGetV2RayUserQrCode();
  const { mutate: getUri, isPending: isLoadingUri } = useGetV2RayUserUri();

  useEffect(() => {
    if (open && user) {
      setQrCodeUrl(null);
      setShareUri(null);
      setQrError(null);
      setUriError(null);

      getQrCode(user.id, {
        onSuccess: (url) => setQrCodeUrl(url),
        onError: (error: Error) => setQrError(error.message),
      });

      getUri(user.id, {
        onSuccess: (data) => setShareUri(data.uri),
        onError: (error: Error) => setUriError(error.message),
      });
    }

    return () => {
      if (qrCodeUrl) {
        URL.revokeObjectURL(qrCodeUrl);
      }
    };
  }, [open, user, getQrCode, getUri]);

  const handleCopyUri = () => {
    if (shareUri) {
      navigator.clipboard.writeText(shareUri);
      toast.success("Share URI copied to clipboard");
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Share V2Ray User: {user?.name}</DialogTitle>
          <DialogDescription>
            Scan the QR code or copy the share URI.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="qrcode" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="qrcode">QR Code</TabsTrigger>
            <TabsTrigger value="uri">Share URI</TabsTrigger>
          </TabsList>
          
          <TabsContent value="qrcode" className="flex flex-col items-center justify-center p-4">
            {isLoadingQr ? (
              <Loader2 className="h-32 w-32 animate-spin text-muted-foreground" />
            ) : qrCodeUrl ? (
              <img src={qrCodeUrl} alt="V2Ray QR Code" className="h-64 w-64 border rounded-lg" />
            ) : (
              <p className="text-destructive text-center">{qrError || "Failed to load QR code"}</p>
            )}
            {qrCodeUrl && (
              <p className="text-sm text-muted-foreground mt-4 text-center">
                Scan this code with a V2Ray/Xray compatible client
              </p>
            )}
          </TabsContent>

          <TabsContent value="uri" className="space-y-4">
            <div className="relative">
              {isLoadingUri ? (
                <div className="flex justify-center p-8">
                  <Loader2 className="h-8 w-8 animate-spin" />
                </div>
              ) : shareUri ? (
                <div className="p-4 rounded-lg bg-muted break-all text-xs font-mono border">
                  {shareUri}
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-destructive/10 text-destructive text-sm border border-destructive/20">
                  {uriError || "Failed to load share URI"}
                </div>
              )}
            </div>
            <div className="flex justify-end">
              <Button variant="outline" size="sm" onClick={handleCopyUri} disabled={!shareUri}>
                <Copy className="mr-2 h-4 w-4" />
                Copy URI
              </Button>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
