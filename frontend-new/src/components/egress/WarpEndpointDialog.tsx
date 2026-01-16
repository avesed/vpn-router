import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Progress } from "../ui/progress";
import { ScrollArea } from "../ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { Alert, AlertDescription } from "../ui/alert";
import { Loader2, Zap, Check, Network } from "lucide-react";
import { useSetWarpEndpoint, useTestWarpEndpoints } from "../../api/hooks/useEgress";
import { toast } from "sonner";
import type { WarpEgress, WarpEndpointResult } from "../../types";

interface WarpEndpointDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  egress: WarpEgress;
}

export function WarpEndpointDialog({ open, onOpenChange, egress }: WarpEndpointDialogProps) {
  const { t } = useTranslation();
  
  const setEndpoint = useSetWarpEndpoint();
  const testEndpoints = useTestWarpEndpoints();

  const [endpointV4, setEndpointV4] = useState("");
  const [endpointV6, setEndpointV6] = useState("");
  const [testResults, setTestResults] = useState<WarpEndpointResult[]>([]);
  const [testProgress, setTestProgress] = useState<{ current: number; total: number } | null>(null);

  // Initialize from egress
  useEffect(() => {
    if (open && egress) {
      setEndpointV4(egress.endpoint_v4 || "");
      setEndpointV6(egress.endpoint_v6 || "");
      setTestResults([]);
      setTestProgress(null);
    }
  }, [open, egress]);

  const handleTestEndpoints = async () => {
    try {
      setTestProgress({ current: 0, total: 100 });
      const result = await testEndpoints.mutateAsync({
        sample_count: 10,
        top_n: 20,
      });
      setTestResults(result.results);
      setTestProgress(null);
      toast.success(t("egress.warp.testComplete", { defaultValue: "Endpoint test complete" }));
    } catch (error) {
      setTestProgress(null);
      toast.error(t("egress.warp.testFailed", { defaultValue: "Endpoint test failed" }));
    }
  };

  const handleSelectEndpoint = (endpoint: WarpEndpointResult) => {
    if (endpoint.ip.includes(":")) {
      setEndpointV6(`[${endpoint.ip}]:${endpoint.port}`);
    } else {
      setEndpointV4(`${endpoint.ip}:${endpoint.port}`);
    }
    toast.success(t("egress.warp.endpointSelected", { defaultValue: "Endpoint selected" }));
  };

  const handleSave = async () => {
    try {
      await setEndpoint.mutateAsync({
        tag: egress.tag,
        data: {
          endpoint_v4: endpointV4.trim() || undefined,
          endpoint_v6: endpointV6.trim() || undefined,
        }
      });
      toast.success(t("egress.warp.endpointSaved", { defaultValue: "Endpoint saved" }));
      onOpenChange(false);
    } catch (error) {
      toast.error(t("egress.warp.endpointSaveFailed", { defaultValue: "Failed to save endpoint" }));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>
            {t("egress.warp.endpointTitle", { defaultValue: "WARP Endpoint Settings" })} - {egress.tag}
          </DialogTitle>
          <DialogDescription>
            {t("egress.warp.endpointDescription", { 
              defaultValue: "Configure WARP endpoint or test to find the best endpoint" 
            })}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 flex-1 overflow-hidden flex flex-col">
          {/* Current Endpoints */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="endpointV4">
                {t("egress.warp.endpointV4", { defaultValue: "IPv4 Endpoint" })}
              </Label>
              <Input
                id="endpointV4"
                value={endpointV4}
                onChange={(e) => setEndpointV4(e.target.value)}
                placeholder="162.159.192.1:500"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="endpointV6">
                {t("egress.warp.endpointV6", { defaultValue: "IPv6 Endpoint" })}
              </Label>
              <Input
                id="endpointV6"
                value={endpointV6}
                onChange={(e) => setEndpointV6(e.target.value)}
                placeholder="[2606:4700:d0::a29f:c001]:500"
              />
            </div>
          </div>

          {/* Test Button */}
          <div className="flex items-center gap-2">
            <Button 
              variant="outline" 
              onClick={handleTestEndpoints}
              disabled={testEndpoints.isPending}
            >
              {testEndpoints.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Zap className="mr-2 h-4 w-4" />
              )}
              {t("egress.warp.testEndpoints", { defaultValue: "Test Endpoints" })}
            </Button>
            {testProgress && (
              <div className="flex-1">
                <Progress value={(testProgress.current / testProgress.total) * 100} className="h-2" />
              </div>
            )}
          </div>

          {/* Test Results */}
          {testResults.length > 0 && (
            <div className="flex-1 overflow-hidden border rounded-lg">
              <ScrollArea className="h-[300px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[200px]">{t("egress.warp.endpoint", { defaultValue: "Endpoint" })}</TableHead>
                      <TableHead className="text-right">{t("egress.warp.latency", { defaultValue: "Latency" })}</TableHead>
                      <TableHead className="text-right">{t("egress.warp.lossRate", { defaultValue: "Loss" })}</TableHead>
                      <TableHead className="w-[100px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {testResults.map((result, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono text-xs">
                          {result.endpoint}
                        </TableCell>
                        <TableCell className="text-right">
                          <span className={
                            result.latency_ms < 100 ? "text-green-500" :
                            result.latency_ms < 200 ? "text-yellow-500" : "text-red-500"
                          }>
                            {result.latency_ms.toFixed(0)}ms
                          </span>
                        </TableCell>
                        <TableCell className="text-right">
                          <span className={result.loss_rate > 0.2 ? "text-red-500" : ""}>
                            {(result.loss_rate * 100).toFixed(0)}%
                          </span>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleSelectEndpoint(result)}
                          >
                            <Check className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </ScrollArea>
            </div>
          )}

          {testResults.length === 0 && !testEndpoints.isPending && (
            <Alert>
              <Network className="h-4 w-4" />
              <AlertDescription>
                {t("egress.warp.testHint", { 
                  defaultValue: "Click 'Test Endpoints' to find the best WARP endpoint for your location" 
                })}
              </AlertDescription>
            </Alert>
          )}
        </div>

        <DialogFooter className="mt-4">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button onClick={handleSave} disabled={setEndpoint.isPending}>
            {setEndpoint.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t("common.save", { defaultValue: "Save" })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// WARP License Dialog
interface WarpLicenseDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  egress: WarpEgress;
}

export function WarpLicenseDialog({ open, onOpenChange, egress }: WarpLicenseDialogProps) {
  const { t } = useTranslation();
  const [licenseKey, setLicenseKey] = useState("");
  
  const applyLicense = useApplyWarpLicense();

  useEffect(() => {
    if (open) {
      setLicenseKey("");
    }
  }, [open]);

  const handleApply = async () => {
    if (!licenseKey.trim()) return;

    try {
      await applyLicense.mutateAsync({
        tag: egress.tag,
        data: { license_key: licenseKey.trim() }
      });
      toast.success(t("egress.warp.licenseApplied", { defaultValue: "License applied successfully" }));
      onOpenChange(false);
    } catch (error) {
      toast.error(t("egress.warp.licenseApplyFailed", { defaultValue: "Failed to apply license" }));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {t("egress.warp.licenseTitle", { defaultValue: "Apply WARP+ License" })}
          </DialogTitle>
          <DialogDescription>
            {t("egress.warp.licenseDescription", { 
              defaultValue: "Enter your WARP+ license key to upgrade from free account" 
            })}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="licenseKey">
              {t("egress.warp.licenseKey", { defaultValue: "License Key" })}
            </Label>
            <Input
              id="licenseKey"
              value={licenseKey}
              onChange={(e) => setLicenseKey(e.target.value)}
              placeholder="XXXXXXXX-XXXXXXXX-XXXXXXXX"
            />
            <p className="text-xs text-muted-foreground">
              {t("egress.warp.licenseHint", { 
                defaultValue: "You can get a WARP+ license from Cloudflare or 1.1.1.1 mobile app" 
              })}
            </p>
          </div>

          <div className="text-sm text-muted-foreground">
            <p>{t("egress.warp.currentType", { defaultValue: "Current account type" })}: 
              <span className="ml-2 font-medium">
                {egress.account_type === "warp+" ? "WARP+" : 
                 egress.account_type === "teams" ? "Teams" : "Free"}
              </span>
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button onClick={handleApply} disabled={!licenseKey.trim() || applyLicense.isPending}>
            {applyLicense.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t("egress.warp.applyLicense", { defaultValue: "Apply License" })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// Import the hook
import { useApplyWarpLicense } from "../../api/hooks/useEgress";
