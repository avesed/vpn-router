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
import { useCreateV2RayEgress, useUpdateV2RayEgress, useParseV2RayURI } from "../../api/hooks/useEgress";
import type { V2RayEgress, V2RayProtocol, V2RayTransport } from "../../types";
import { V2RAY_TRANSPORTS, V2RAY_SECURITY_OPTIONS, V2RAY_TLS_FINGERPRINTS, VLESS_FLOW_OPTIONS } from "../../types";

interface AddV2RayDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editEgress?: V2RayEgress;
}

export function AddV2RayDialog({ open, onOpenChange, editEgress }: AddV2RayDialogProps) {
  const { t } = useTranslation();
  
  const createMutation = useCreateV2RayEgress();
  const updateMutation = useUpdateV2RayEgress();
  const parseMutation = useParseV2RayURI();

  const isEditing = !!editEgress;

  // Import method
  const [importMethod, setImportMethod] = useState<"uri" | "manual">("uri");
  const [uriInput, setUriInput] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);

  // Form fields
  const [tag, setTag] = useState("");
  const [description, setDescription] = useState("");
  const [protocol, setProtocol] = useState<V2RayProtocol>("vless");
  const [server, setServer] = useState("");
  const [serverPort, setServerPort] = useState(443);
  const [uuid, setUuid] = useState("");
  const [password, setPassword] = useState("");
  const [security, setSecurity] = useState("auto");
  const [alterId, setAlterId] = useState(0);
  const [flow, setFlow] = useState("none");

  // TLS
  const [tlsEnabled, setTlsEnabled] = useState(true);
  const [tlsSni, setTlsSni] = useState("");
  const [tlsFingerprint, setTlsFingerprint] = useState("default");
  const [tlsAllowInsecure, setTlsAllowInsecure] = useState(false);
  
  // REALITY
  const [realityEnabled, setRealityEnabled] = useState(false);
  const [realityPublicKey, setRealityPublicKey] = useState("");
  const [realityShortId, setRealityShortId] = useState("");
  
  // Transport
  const [transportType, setTransportType] = useState<V2RayTransport>("tcp");
  const [transportPath, setTransportPath] = useState("");
  const [transportHost, setTransportHost] = useState("");
  const [transportServiceName, setTransportServiceName] = useState("");

  // Reset form
  const resetForm = () => {
    setTag("");
    setDescription("");
    setProtocol("vless");
    setServer("");
    setServerPort(443);
    setUuid("");
    setPassword("");
    setSecurity("auto");
    setAlterId(0);
    setFlow("none");
    setTlsEnabled(true);
    setTlsSni("");
    setTlsFingerprint("default");
    setTlsAllowInsecure(false);
    setRealityEnabled(false);
    setRealityPublicKey("");
    setRealityShortId("");
    setTransportType("tcp");
    setTransportPath("");
    setTransportHost("");
    setTransportServiceName("");
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
        setProtocol(editEgress.protocol);
        setServer(editEgress.server);
        setServerPort(editEgress.server_port);
        setUuid(editEgress.uuid || "");
        setPassword(""); // Password is hidden by API
        setSecurity(editEgress.security || "auto");
        setAlterId(editEgress.alter_id || 0);
        setFlow(editEgress.flow || "none");
        setTlsEnabled(editEgress.tls_enabled === 1);
        setTlsSni(editEgress.tls_sni || "");
        setTlsFingerprint(editEgress.tls_fingerprint || "default");
        setTlsAllowInsecure(editEgress.tls_allow_insecure === 1);
        setRealityEnabled(editEgress.reality_enabled === 1);
        setRealityPublicKey(editEgress.reality_public_key || "");
        setRealityShortId(editEgress.reality_short_id || "");
        setTransportType(editEgress.transport_type);
        
        // Parse transport config if available
        if (editEgress.transport_config) {
          try {
            const config = typeof editEgress.transport_config === "string"
              ? JSON.parse(editEgress.transport_config)
              : editEgress.transport_config;
            setTransportPath(config.path || "");
            setTransportHost(config.host || "");
            setTransportServiceName(config.service_name || "");
          } catch {
            // Ignore parse errors
          }
        }
        setImportMethod("manual");
      } else {
        resetForm();
      }
    }
  }, [open, editEgress]);

  const handleParseUri = async () => {
    if (!uriInput.trim()) {
      setParseError(t("egress.v2ray.uriRequired", { defaultValue: "Please enter a V2Ray URI" }));
      return;
    }

    try {
      setParseError(null);
      const result = await parseMutation.mutateAsync(uriInput.trim());
      
      // Populate form fields from parsed result
      if (result.protocol) setProtocol(result.protocol);
      if (result.server) setServer(result.server);
      if (result.server_port) setServerPort(result.server_port);
      if (result.uuid) setUuid(result.uuid);
      if (result.password) setPassword(result.password);
      if (result.security) setSecurity(result.security);
      if (result.alter_id !== undefined) setAlterId(result.alter_id);
      if (result.flow) setFlow(result.flow); else setFlow("none");
      if (result.tls_enabled !== undefined) setTlsEnabled(result.tls_enabled);
      if (result.tls_sni) setTlsSni(result.tls_sni);
      if (result.tls_fingerprint) setTlsFingerprint(result.tls_fingerprint); else setTlsFingerprint("default");
      if (result.tls_allow_insecure !== undefined) setTlsAllowInsecure(result.tls_allow_insecure);
      if (result.reality_enabled !== undefined) setRealityEnabled(result.reality_enabled);
      if (result.reality_public_key) setRealityPublicKey(result.reality_public_key);
      if (result.reality_short_id) setRealityShortId(result.reality_short_id);
      if (result.transport_type) setTransportType(result.transport_type);
      if (result.transport_config?.path) setTransportPath(result.transport_config.path);
      if (result.transport_config?.host) setTransportHost(result.transport_config.host);
      if (result.transport_config?.service_name) setTransportServiceName(result.transport_config.service_name);
      
      // Generate tag from remark or server
      if (result.remark) {
        setTag(result.remark.toLowerCase().replace(/[^a-z0-9-]/g, "-"));
      } else if (result.server) {
        setTag(result.server.split(".")[0].toLowerCase().replace(/[^a-z0-9-]/g, "-"));
      }
      
      setImportMethod("manual");
    } catch (err) {
      setParseError(err instanceof Error ? err.message : "Failed to parse URI");
    }
  };

  const handleSubmit = async () => {
    if (!tag.trim() || !server.trim()) return;

    // Validate auth based on protocol
    if (protocol === "trojan" && !password) return;
    if ((protocol === "vmess" || protocol === "vless") && !uuid) return;

    try {
      // Build transport config
      const transportConfig: Record<string, string> = {};
      if (transportPath) transportConfig.path = transportPath;
      if (transportHost) transportConfig.host = transportHost;
      if (transportServiceName) transportConfig.service_name = transportServiceName;

      // Convert special values back to API format (empty string or undefined)
      const flowValue = flow === "none" ? undefined : flow || undefined;
      const fingerprintValue = tlsFingerprint === "default" ? undefined : tlsFingerprint || undefined;

      if (isEditing) {
        await updateMutation.mutateAsync({
          tag: editEgress.tag,
          data: {
            description,
            protocol,
            server,
            server_port: serverPort,
            uuid: uuid || undefined,
            password: password || undefined,
            security,
            alter_id: alterId,
            flow: flowValue,
            tls_enabled: tlsEnabled,
            tls_sni: tlsSni || undefined,
            tls_fingerprint: fingerprintValue,
            tls_allow_insecure: tlsAllowInsecure,
            reality_enabled: realityEnabled,
            reality_public_key: realityPublicKey || undefined,
            reality_short_id: realityShortId || undefined,
            transport_type: transportType,
            transport_config: Object.keys(transportConfig).length > 0 ? transportConfig : undefined,
          }
        });
      } else {
        await createMutation.mutateAsync({
          tag: tag.trim(),
          description,
          protocol,
          server,
          server_port: serverPort,
          uuid: uuid || undefined,
          password: password || undefined,
          security,
          alter_id: alterId,
          flow: flowValue,
          tls_enabled: tlsEnabled,
          tls_sni: tlsSni || undefined,
          tls_fingerprint: fingerprintValue,
          tls_allow_insecure: tlsAllowInsecure,
          reality_enabled: realityEnabled,
          reality_public_key: realityPublicKey || undefined,
          reality_short_id: realityShortId || undefined,
          transport_type: transportType,
          transport_config: Object.keys(transportConfig).length > 0 ? transportConfig : undefined,
        });
      }
      onOpenChange(false);
    } catch {
      // Error handled by mutation
    }
  };

  const isSubmitting = createMutation.isPending || updateMutation.isPending;

  // Determine if auth field is valid
  const isAuthValid = protocol === "trojan" 
    ? !!password 
    : (protocol === "vmess" || protocol === "vless") 
      ? !!uuid 
      : true;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {isEditing
              ? t("egress.v2ray.editTitle", { defaultValue: "Edit V2Ray Egress" })
              : t("egress.v2ray.addTitle", { defaultValue: "Add V2Ray Egress" })}
          </DialogTitle>
          <DialogDescription>
            {isEditing
              ? t("egress.v2ray.editDescription", { defaultValue: "Update V2Ray/Xray outbound configuration" })
              : t("egress.v2ray.addDescription", { defaultValue: "Add a new V2Ray/Xray outbound proxy" })}
          </DialogDescription>
        </DialogHeader>

        <Tabs value={importMethod} onValueChange={(v) => setImportMethod(v as typeof importMethod)}>
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="uri" disabled={isEditing}>
              {t("egress.v2ray.importUri", { defaultValue: "Import URI" })}
            </TabsTrigger>
            <TabsTrigger value="manual">
              {t("egress.v2ray.manual", { defaultValue: "Manual" })}
            </TabsTrigger>
          </TabsList>

          {/* URI Import Tab */}
          <TabsContent value="uri" className="space-y-4">
            <div className="space-y-2">
              <Label>{t("egress.v2ray.uri", { defaultValue: "V2Ray URI" })}</Label>
              <Textarea
                value={uriInput}
                onChange={(e) => setUriInput(e.target.value)}
                placeholder="vless://uuid@server:port?..."
                className="font-mono text-xs min-h-[100px]"
              />
              <p className="text-xs text-muted-foreground">
                {t("egress.v2ray.uriHint", { 
                  defaultValue: "Supports vless://, vmess://, trojan:// URIs" 
                })}
              </p>
            </div>
            <Button onClick={handleParseUri} disabled={parseMutation.isPending}>
              {parseMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              <Link2 className="mr-2 h-4 w-4" />
              {t("egress.v2ray.parseUri", { defaultValue: "Parse URI" })}
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
                  placeholder="v2ray-server"
                  disabled={isEditing}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">{t("common.description", { defaultValue: "Description" })}</Label>
                <Input
                  id="description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="My V2Ray Server"
                />
              </div>
            </div>

            {/* Protocol & Server */}
            <div className="grid grid-cols-4 gap-4">
              <div className="space-y-2">
                <Label>{t("egress.v2ray.protocol", { defaultValue: "Protocol" })}</Label>
                <Select value={protocol} onValueChange={(v) => setProtocol(v as V2RayProtocol)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="vless">VLESS</SelectItem>
                    <SelectItem value="vmess">VMess</SelectItem>
                    <SelectItem value="trojan">Trojan</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="col-span-2 space-y-2">
                <Label htmlFor="server">{t("egress.v2ray.server", { defaultValue: "Server" })}</Label>
                <Input
                  id="server"
                  value={server}
                  onChange={(e) => setServer(e.target.value)}
                  placeholder="server.example.com"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="serverPort">{t("egress.v2ray.port", { defaultValue: "Port" })}</Label>
                <Input
                  id="serverPort"
                  type="number"
                  value={serverPort}
                  onChange={(e) => setServerPort(parseInt(e.target.value) || 443)}
                />
              </div>
            </div>

            {/* Authentication */}
            <div className="grid grid-cols-2 gap-4">
              {(protocol === "vmess" || protocol === "vless") && (
                <div className="space-y-2">
                  <Label htmlFor="uuid">UUID *</Label>
                  <Input
                    id="uuid"
                    value={uuid}
                    onChange={(e) => setUuid(e.target.value)}
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  />
                </div>
              )}
              {protocol === "trojan" && (
                <div className="space-y-2">
                  <Label htmlFor="password">{t("egress.v2ray.password", { defaultValue: "Password" })} *</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
              )}
              {protocol === "vmess" && (
                <>
                  <div className="space-y-2">
                    <Label>{t("egress.v2ray.security", { defaultValue: "Security" })}</Label>
                    <Select value={security} onValueChange={setSecurity}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {V2RAY_SECURITY_OPTIONS.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="alterId">{t("egress.v2ray.alterId", { defaultValue: "Alter ID" })}</Label>
                    <Input
                      id="alterId"
                      type="number"
                      value={alterId}
                      onChange={(e) => setAlterId(parseInt(e.target.value) || 0)}
                    />
                  </div>
                </>
              )}
              {protocol === "vless" && (
                <div className="space-y-2">
                  <Label>{t("egress.v2ray.flow", { defaultValue: "Flow" })}</Label>
                  <Select value={flow} onValueChange={setFlow}>
                    <SelectTrigger>
                      <SelectValue placeholder="None" />
                    </SelectTrigger>
                    <SelectContent>
                      {VLESS_FLOW_OPTIONS.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>

            {/* TLS Settings */}
            <div className="space-y-4 border rounded-lg p-4">
              <div className="flex items-center justify-between">
                <Label>{t("egress.v2ray.tls", { defaultValue: "TLS" })}</Label>
                <Switch checked={tlsEnabled} onCheckedChange={setTlsEnabled} />
              </div>
              
              {tlsEnabled && !realityEnabled && (
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="tlsSni">SNI</Label>
                    <Input
                      id="tlsSni"
                      value={tlsSni}
                      onChange={(e) => setTlsSni(e.target.value)}
                      placeholder="server.example.com"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>{t("egress.v2ray.fingerprint", { defaultValue: "Fingerprint" })}</Label>
                    <Select value={tlsFingerprint} onValueChange={setTlsFingerprint}>
                      <SelectTrigger>
                        <SelectValue placeholder="Default" />
                      </SelectTrigger>
                      <SelectContent>
                        {V2RAY_TLS_FINGERPRINTS.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-center space-x-2 col-span-2">
                    <Switch 
                      id="tlsAllowInsecure" 
                      checked={tlsAllowInsecure} 
                      onCheckedChange={setTlsAllowInsecure} 
                    />
                    <Label htmlFor="tlsAllowInsecure" className="text-sm">
                      {t("egress.v2ray.allowInsecure", { defaultValue: "Allow Insecure" })}
                    </Label>
                  </div>
                </div>
              )}
            </div>

            {/* REALITY Settings (VLESS only) */}
            {protocol === "vless" && (
              <div className="space-y-4 border rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <Label>REALITY</Label>
                  <Switch checked={realityEnabled} onCheckedChange={setRealityEnabled} />
                </div>
                
                {realityEnabled && (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="realityPublicKey">{t("egress.v2ray.realityPublicKey", { defaultValue: "Public Key" })}</Label>
                      <Input
                        id="realityPublicKey"
                        value={realityPublicKey}
                        onChange={(e) => setRealityPublicKey(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="realityShortId">{t("egress.v2ray.realityShortId", { defaultValue: "Short ID" })}</Label>
                      <Input
                        id="realityShortId"
                        value={realityShortId}
                        onChange={(e) => setRealityShortId(e.target.value)}
                      />
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Transport Settings */}
            <div className="space-y-4 border rounded-lg p-4">
              <div className="space-y-2">
                <Label>{t("egress.v2ray.transport", { defaultValue: "Transport" })}</Label>
                <Select value={transportType} onValueChange={(v) => setTransportType(v as V2RayTransport)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {V2RAY_TRANSPORTS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {(transportType === "ws" || transportType === "h2" || transportType === "httpupgrade" || transportType === "xhttp") && (
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="transportPath">{t("egress.v2ray.path", { defaultValue: "Path" })}</Label>
                    <Input
                      id="transportPath"
                      value={transportPath}
                      onChange={(e) => setTransportPath(e.target.value)}
                      placeholder="/"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="transportHost">{t("egress.v2ray.host", { defaultValue: "Host" })}</Label>
                    <Input
                      id="transportHost"
                      value={transportHost}
                      onChange={(e) => setTransportHost(e.target.value)}
                    />
                  </div>
                </div>
              )}

              {transportType === "grpc" && (
                <div className="space-y-2">
                  <Label htmlFor="transportServiceName">{t("egress.v2ray.serviceName", { defaultValue: "Service Name" })}</Label>
                  <Input
                    id="transportServiceName"
                    value={transportServiceName}
                    onChange={(e) => setTransportServiceName(e.target.value)}
                  />
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={!tag.trim() || !server.trim() || !isAuthValid || isSubmitting}
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
