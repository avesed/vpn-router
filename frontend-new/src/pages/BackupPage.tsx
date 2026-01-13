import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useBackupStatus, useExportBackup, useImportBackup } from "@/api/hooks/useBackup";
import { Loader2, Download, Upload, ShieldCheck, Database, Key } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { formatBytes } from "@/lib/utils";

const passwordSchema = z.object({
  password: z.string().min(1, "Password is required"),
});

export default function BackupPage() {
  const { data: status, isLoading: isLoadingStatus } = useBackupStatus();
  const { mutate: exportBackup, isPending: isExporting } = useExportBackup();
  const { mutate: importBackup, isPending: isImporting } = useImportBackup();

  const {
    register: registerExport,
    handleSubmit: handleSubmitExport,
    formState: { errors: exportErrors },
  } = useForm<{ password: string }>({
    resolver: zodResolver(passwordSchema),
  });

  const {
    register: registerImport,
    handleSubmit: handleSubmitImport,
    formState: { errors: importErrors },
  } = useForm<{ password: string; file: FileList }>({
    resolver: zodResolver(
      z.object({
        password: z.string().min(1, "Password is required"),
        file: z.any().refine((files) => files?.length > 0, "File is required"),
      })
    ),
  });

  const onExport = (data: { password: string }) => {
    exportBackup(data.password, {
      onSuccess: (response) => {
        // Create download link
        const blob = new Blob([JSON.stringify(response.backup, null, 2)], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `vpn-router-backup-${new Date().toISOString().split("T")[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      },
    });
  };

  const onImport = (data: { password: string; file: FileList }) => {
    const file = data.file[0];
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      importBackup({ data: content, password: data.password });
    };
    reader.readAsText(file);
  };

  if (isLoadingStatus) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Backup & Restore</h1>
        <p className="text-muted-foreground">
          Manage system configuration backups with encryption.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>System Status</CardTitle>
            <CardDescription>Current configuration overview</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <p className="text-sm font-medium text-muted-foreground">Database Size</p>
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4 text-primary" />
                  <span className="font-bold">{formatBytes(status?.database_size_bytes || 0)}</span>
                </div>
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium text-muted-foreground">Encryption</p>
                <div className="flex items-center gap-2">
                  <ShieldCheck className={`h-4 w-4 ${status?.database_encrypted ? "text-green-500" : "text-yellow-500"}`} />
                  <span className="font-bold">{status?.database_encrypted ? "Enabled" : "Disabled"}</span>
                </div>
              </div>
            </div>

            <Separator />

            <div className="space-y-2">
              <p className="text-sm font-medium">Configuration Items</p>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Ingress Peers:</span>
                  <span>{status?.ingress_peer_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Custom Egress:</span>
                  <span>{status?.custom_egress_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">PIA Profiles:</span>
                  <span>{status?.pia_profile_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">PIA Credentials:</span>
                  <span>{status?.has_pia_credentials ? "Yes" : "No"}</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Export Backup</CardTitle>
              <CardDescription>Download an encrypted backup of your configuration</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmitExport(onExport)} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="export-password">Encryption Password</Label>
                  <div className="relative">
                    <Key className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="export-password"
                      type="password"
                      placeholder="Enter password to encrypt backup"
                      className="pl-9"
                      {...registerExport("password")}
                    />
                  </div>
                  {exportErrors.password && (
                    <p className="text-sm text-destructive">{exportErrors.password.message}</p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    This password will be required to restore the backup. Do not lose it.
                  </p>
                </div>
                <Button type="submit" className="w-full" disabled={isExporting}>
                  {isExporting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />}
                  Export Configuration
                </Button>
              </form>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Restore Backup</CardTitle>
              <CardDescription>Restore configuration from a backup file</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmitImport(onImport)} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="import-file">Backup File</Label>
                  <div className="flex gap-2">
                    <Input
                      id="import-file"
                      type="file"
                      accept=".json"
                      className="cursor-pointer"
                      {...registerImport("file")}
                    />
                  </div>
                  {importErrors.file && (
                    <p className="text-sm text-destructive">{importErrors.file.message as string}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="import-password">Decryption Password</Label>
                  <div className="relative">
                    <Key className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="import-password"
                      type="password"
                      placeholder="Enter password to decrypt backup"
                      className="pl-9"
                      {...registerImport("password")}
                    />
                  </div>
                  {importErrors.password && (
                    <p className="text-sm text-destructive">{importErrors.password.message}</p>
                  )}
                </div>

                <Alert variant="destructive">
                  <AlertTitle>Warning</AlertTitle>
                  <AlertDescription>
                    Restoring a backup will overwrite the current configuration. The system will reload after restore.
                  </AlertDescription>
                </Alert>

                <Button type="submit" variant="destructive" className="w-full" disabled={isImporting}>
                  {isImporting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Upload className="mr-2 h-4 w-4" />}
                  Restore Configuration
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
