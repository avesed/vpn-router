import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Textarea } from "../ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Switch } from "../ui/switch";
import { Alert, AlertDescription } from "../ui/alert";
import { Loader2, AlertTriangle, Link2 } from "lucide-react";
import { useCreateShadowsocksEgress, useUpdateShadowsocksEgress, useParseShadowsocksURI } from "../../api/hooks/useEgress";
import type { ShadowsocksOutbound, ShadowsocksMethod } from "../../types";
import { SHADOWSOCKS_METHODS } from "../../types";

interface AddShadowsocksDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editEgress?: ShadowsocksOutbound;
}

export function AddShadowsocksDialog({ open, onOpenChange, editEgress }: AddShadowsocksDialogProps) {
  const { t } = useTranslation();

  const createMutation = useCreateShadowsocksEgress();
  const updateMutation = useUpdateShadowsocksEgress();
  const parseMutation = useParseShadowsocksURI();

  const isEditing = !!editEgress;

  // Import method
  const [importMethod, setImportMethod] = useState<"uri" | "manual">("uri");
  const [uriInput, setUriInput] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);

  // Form fields
  const [tag, setTag] = useState("");
  const [description, setDescription] = useState("");
  const [server, setServer] = useState("");
  const [serverPort, setServerPort] = useState(8388);
  const [method, setMethod] = useState<ShadowsocksMethod>("2022-blake3-aes-256-gcm");
  const [password, setPassword] = useState("");
  const [udpEnabled, setUdpEnabled] = useState(true);

  // Reset form
  const resetForm = () => {
    setTag("");
    setDescription("");
    setServer("");
    setServerPort(8388);
    setMethod("2022-blake3-aes-256-gcm");
    setPassword("");
    setUdpEnabled(true);
    setUriInput("");
    setParseError(null);
    setImportMethod("uri");
  };

  // Initialize form when dialog opens
  useEffect(() => {
    if (open) {
      if (editEgress) {
        setTag(editEgress.tag);
        setDescription(editEgress.description || "");
        setServer(editEgress.server);
        setServerPort(editEgress.server_port);
        setMethod(editEgress.method);
        setPassword(""); // Password is hidden by API
        setUdpEnabled(editEgress.udp);
        setImportMethod("manual");
      } else {
        resetForm();
      }
    }
  }, [open, editEgress]);

  const handleParseUri = async () => {
    if (!uriInput.trim()) {
      setParseError(t("egress.shadowsocks.uriRequired", { defaultValue: "Please enter a Shadowsocks URI" }));
      return;
    }

    try {
      setParseError(null);
      const result = await parseMutation.mutateAsync(uriInput.trim());

      // Populate form fields from parsed result
      if (result.server) setServer(result.server);
      if (result.server_port) setServerPort(result.server_port);
      if (result.method) setMethod(result.method);
      if (result.password) setPassword(result.password);

      // Generate tag from server or remark
      if (result.tag) {
        setTag(result.tag.toLowerCase().replace(/[^a-z0-9-]/g, "-"));
      } else if (result.server) {
        setTag(result.server.split(".")[0].toLowerCase().replace(/[^a-z0-9-]/g, "-"));
      }

      setImportMethod("manual");
    } catch (err) {
      setParseError(err instanceof Error ? err.message : "Failed to parse URI");
    }
  };

  const handleSubmit = async () => {
    if (!tag.trim() || !server.trim() || !password) return;

    try {
      if (isEditing) {
        await updateMutation.mutateAsync({
          tag: editEgress.tag,
          data: {
            description,
            server,
            server_port: serverPort,
            method,
            password: password || undefined,
            udp: udpEnabled,
          }
        });
      } else {
        await createMutation.mutateAsync({
          tag: tag.trim(),
          description,
          server,
          server_port: serverPort,
          method,
          password,
          udp: udpEnabled,
        });
      }
      onOpenChange(false);
    } catch {
      // Error handled by mutation
    }
  };

  const isSubmitting = createMutation.isPending || updateMutation.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {isEditing
              ? t("egress.shadowsocks.editTitle", { defaultValue: "Edit Shadowsocks Egress" })
              : t("egress.shadowsocks.addTitle", { defaultValue: "Add Shadowsocks Egress" })}
          </DialogTitle>
          <DialogDescription>
            {isEditing
              ? t("egress.shadowsocks.editDescription", { defaultValue: "Update Shadowsocks outbound configuration" })
              : t("egress.shadowsocks.addDescription", { defaultValue: "Add a new Shadowsocks outbound proxy" })}
          </DialogDescription>
        </DialogHeader>

        <Tabs value={importMethod} onValueChange={(v) => setImportMethod(v as typeof importMethod)}>
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="uri" disabled={isEditing}>
              {t("egress.shadowsocks.importUri", { defaultValue: "Import URI" })}
            </TabsTrigger>
            <TabsTrigger value="manual">
              {t("egress.shadowsocks.manual", { defaultValue: "Manual" })}
            </TabsTrigger>
          </TabsList>

          {/* URI Import Tab */}
          <TabsContent value="uri" className="space-y-4">
            <div className="space-y-2">
              <Label>{t("egress.shadowsocks.uri", { defaultValue: "Shadowsocks URI" })}</Label>
              <Textarea
                value={uriInput}
                onChange={(e) => setUriInput(e.target.value)}
                placeholder="ss://base64...@server:port#name"
                className="font-mono text-xs min-h-[100px]"
              />
              <p className="text-xs text-muted-foreground">
                {t("egress.shadowsocks.uriHint", {
                  defaultValue: "Supports ss:// URIs"
                })}
              </p>
            </div>
            <Button onClick={handleParseUri} disabled={parseMutation.isPending}>
              {parseMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              <Link2 className="mr-2 h-4 w-4" />
              {t("egress.shadowsocks.parseUri", { defaultValue: "Parse URI" })}
            </Button>
            {parseError && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{parseError}</AlertDescription>
              </Alert>
            )}
          </TabsContent>

          {/* Manual Tab */}
          <TabsContent value="manual" className="space-y-4">
            {/* Basic Info */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="tag">{t("common.tag", { defaultValue: "Tag" })}</Label>
                <Input
                  id="tag"
                  value={tag}
                  onChange={(e) => setTag(e.target.value)}
                  placeholder="ss-server"
                  disabled={isEditing}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">{t("common.description", { defaultValue: "Description" })}</Label>
                <Input
                  id="description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="My Shadowsocks Server"
                />
              </div>
            </div>

            {/* Server */}
            <div className="grid grid-cols-4 gap-4">
              <div className="col-span-3 space-y-2">
                <Label htmlFor="server">{t("egress.shadowsocks.server", { defaultValue: "Server" })}</Label>
                <Input
                  id="server"
                  value={server}
                  onChange={(e) => setServer(e.target.value)}
                  placeholder="server.example.com"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="serverPort">{t("egress.shadowsocks.port", { defaultValue: "Port" })}</Label>
                <Input
                  id="serverPort"
                  type="number"
                  value={serverPort}
                  onChange={(e) => setServerPort(parseInt(e.target.value) || 8388)}
                />
              </div>
            </div>

            {/* Encryption Method */}
            <div className="space-y-2">
              <Label>{t("egress.shadowsocks.method", { defaultValue: "Encryption Method" })}</Label>
              <Select value={method} onValueChange={(v) => setMethod(v as ShadowsocksMethod)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SHADOWSOCKS_METHODS.map((m) => (
                    <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Password */}
            <div className="space-y-2">
              <Label htmlFor="password">{t("egress.shadowsocks.password", { defaultValue: "Password" })} *</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={isEditing ? "(leave blank to keep unchanged)" : ""}
              />
              {method.startsWith("2022-") && (
                <p className="text-xs text-muted-foreground">
                  {t("egress.shadowsocks.ss2022Hint", {
                    defaultValue: "SS2022 methods require a base64-encoded key of the correct length"
                  })}
                </p>
              )}
            </div>

            {/* UDP Support */}
            <div className="flex items-center space-x-2">
              <Switch
                id="udpEnabled"
                checked={udpEnabled}
                onCheckedChange={setUdpEnabled}
              />
              <Label htmlFor="udpEnabled">
                {t("egress.shadowsocks.udp", { defaultValue: "Enable UDP Support" })}
              </Label>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={!tag.trim() || !server.trim() || (!isEditing && !password) || isSubmitting}
          >
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {isEditing
              ? t("common.save", { defaultValue: "Save" })
              : t("common.add", { defaultValue: "Add" })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
