import { useState, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Textarea } from "../ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Alert, AlertDescription } from "../ui/alert";
import { Upload, Loader2, AlertTriangle, FileText } from "lucide-react";
import { useCreateOpenVPNEgress, useUpdateOpenVPNEgress, useParseOpenVPNConfig } from "../../api/hooks/useEgress";
import type { OpenVPNEgress } from "../../types";

interface AddOpenVPNDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editEgress?: OpenVPNEgress;
}

const CIPHER_OPTIONS = [
  "AES-256-GCM", "AES-128-GCM", "AES-256-CBC", "AES-128-CBC",
  "CHACHA20-POLY1305", "BF-CBC"
];

const AUTH_OPTIONS = [
  "SHA256", "SHA384", "SHA512", "SHA1", "MD5"
];

const COMPRESS_OPTIONS = [
  { value: "none", label: "None" },
  { value: "lzo", label: "LZO" },
  { value: "lz4", label: "LZ4" },
  { value: "lz4-v2", label: "LZ4-v2" },
];

export function AddOpenVPNDialog({ open, onOpenChange, editEgress }: AddOpenVPNDialogProps) {
  const { t } = useTranslation();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const authFieldsRef = useRef<HTMLDivElement>(null);
  
  const createMutation = useCreateOpenVPNEgress();
  const updateMutation = useUpdateOpenVPNEgress();
  const parseMutation = useParseOpenVPNConfig();

  const isEditing = !!editEgress;

  // Form state
  const [importMethod, setImportMethod] = useState<"upload" | "paste" | "manual">("upload");
  const [pasteContent, setPasteContent] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const [showAuthHint, setShowAuthHint] = useState(false);
  const [authValidationError, setAuthValidationError] = useState(false);

  // Form fields
  const [tag, setTag] = useState("");
  const [description, setDescription] = useState("");
  const [protocol, setProtocol] = useState<"udp" | "tcp">("udp");
  const [remoteHost, setRemoteHost] = useState("");
  const [remotePort, setRemotePort] = useState(1194);
  const [caCert, setCaCert] = useState("");
  const [clientCert, setClientCert] = useState("");
  const [clientKey, setClientKey] = useState("");
  const [tlsAuth, setTlsAuth] = useState("");
  const [tlsCrypt, setTlsCrypt] = useState("");
  const [crlVerify, setCrlVerify] = useState("");
  const [authUser, setAuthUser] = useState("");
  const [authPass, setAuthPass] = useState("");
  const [cipher, setCipher] = useState("AES-256-GCM");
  const [auth, setAuth] = useState("SHA256");
  const [compress, setCompress] = useState("none");
  const [extraOptions, setExtraOptions] = useState("");

  // Reset form
  const resetForm = () => {
    setTag("");
    setDescription("");
    setProtocol("udp");
    setRemoteHost("");
    setRemotePort(1194);
    setCaCert("");
    setClientCert("");
    setClientKey("");
    setTlsAuth("");
    setTlsCrypt("");
    setCrlVerify("");
    setAuthUser("");
    setAuthPass("");
    setCipher("AES-256-GCM");
    setAuth("SHA256");
    setCompress("none");
    setExtraOptions("");
    setPasteContent("");
    setParseError(null);
    setShowAuthHint(false);
    setAuthValidationError(false);
    setImportMethod("upload");
  };

  // Initialize form when dialog opens
  useEffect(() => {
    if (open) {
      if (editEgress) {
        setTag(editEgress.tag);
        setDescription(editEgress.description || "");
        setProtocol(editEgress.protocol);
        setRemoteHost(editEgress.remote_host);
        setRemotePort(editEgress.remote_port);
        setCaCert(editEgress.ca_cert);
        setClientCert(editEgress.client_cert || "");
        setClientKey(""); // Key is hidden by API
        setTlsAuth(editEgress.tls_auth || "");
        setTlsCrypt(editEgress.tls_crypt || "");
        setCrlVerify(editEgress.crl_verify || "");
        setAuthUser(editEgress.auth_user || "");
        setAuthPass(""); // Password is hidden by API
        setCipher(editEgress.cipher);
        setAuth(editEgress.auth);
        setCompress(editEgress.compress || "none");
        setExtraOptions(editEgress.extra_options || "");
        setImportMethod("manual");
      } else {
        resetForm();
      }
    }
  }, [open, editEgress]);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // File size limit (2MB)
    if (file.size > 2 * 1024 * 1024) {
      setParseError(t("common.fileTooLarge", { defaultValue: "File too large (max 2MB)" }));
      return;
    }

    try {
      const content = await file.text();
      await parseConfig(content);
      const baseName = file.name.replace(/\.(ovpn|conf)$/i, "").toLowerCase().replace(/[^a-z0-9-]/g, "-");
      setTag(baseName);
    } catch (err) {
      setParseError(err instanceof Error ? err.message : "Failed to parse config");
    }
  };

  const parseConfig = async (content: string) => {
    try {
      setParseError(null);
      const result = await parseMutation.mutateAsync(content);
      
      if (result.protocol) setProtocol(result.protocol as "udp" | "tcp");
      if (result.remote_host) setRemoteHost(result.remote_host);
      if (result.remote_port) setRemotePort(result.remote_port);
      if (result.ca_cert) setCaCert(result.ca_cert);
      if (result.client_cert) setClientCert(result.client_cert);
      if (result.client_key) setClientKey(result.client_key);
      if (result.tls_auth) setTlsAuth(result.tls_auth);
      if (result.tls_crypt) setTlsCrypt(result.tls_crypt);
      if (result.crl_verify) setCrlVerify(result.crl_verify);
      if (result.cipher) setCipher(result.cipher.toUpperCase());
      if (result.auth) setAuth(result.auth.toUpperCase());
      if (result.compress) setCompress(result.compress); else setCompress("none");
      
      setShowAuthHint(!!result.requires_auth);
      setImportMethod("manual");
    } catch (err) {
      setParseError(err instanceof Error ? err.message : "Failed to parse config");
      throw err;
    }
  };

  const handlePasteConfig = async () => {
    if (!pasteContent.trim()) {
      setParseError(t("egress.openvpn.pasteContentError", { defaultValue: "Please paste the config content" }));
      return;
    }
    try {
      await parseConfig(pasteContent);
    } catch {
      // Error already handled
    }
  };

  const handleSubmit = async () => {
    if (!tag.trim() || !remoteHost.trim() || !caCert.trim()) {
      return;
    }

    // Check if auth is required but not filled
    if (showAuthHint && !authUser && !authPass) {
      setAuthValidationError(true);
      authFieldsRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      return;
    }
    setAuthValidationError(false);

    try {
      if (isEditing) {
        await updateMutation.mutateAsync({
          tag: editEgress.tag,
          data: {
            description,
            protocol,
            remote_host: remoteHost,
            remote_port: remotePort,
            ca_cert: caCert,
            client_cert: clientCert || undefined,
            client_key: clientKey || undefined,
            tls_auth: tlsAuth || undefined,
            tls_crypt: tlsCrypt || undefined,
            crl_verify: crlVerify || undefined,
            auth_user: authUser || undefined,
            auth_pass: authPass || undefined,
            cipher,
            auth,
            compress: compress === "none" ? undefined : compress || undefined,
            extra_options: extraOptions || undefined,
          }
        });
      } else {
        await createMutation.mutateAsync({
          tag: tag.trim(),
          description,
          protocol,
          remote_host: remoteHost,
          remote_port: remotePort,
          ca_cert: caCert,
          client_cert: clientCert || undefined,
          client_key: clientKey || undefined,
          tls_auth: tlsAuth || undefined,
          tls_crypt: tlsCrypt || undefined,
          crl_verify: crlVerify || undefined,
          auth_user: authUser || undefined,
          auth_pass: authPass || undefined,
          cipher,
          auth,
          compress: compress || undefined,
          extra_options: extraOptions || undefined,
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
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {isEditing
              ? t("egress.openvpn.editTitle", { defaultValue: "Edit OpenVPN Egress" })
              : t("egress.openvpn.addTitle", { defaultValue: "Add OpenVPN Egress" })}
          </DialogTitle>
          <DialogDescription>
            {isEditing
              ? t("egress.openvpn.editDescription", { defaultValue: "Update OpenVPN outbound configuration" })
              : t("egress.openvpn.addDescription", { defaultValue: "Add a new OpenVPN outbound connection" })}
          </DialogDescription>
        </DialogHeader>

        <Tabs value={importMethod} onValueChange={(v) => setImportMethod(v as typeof importMethod)}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="upload" disabled={isEditing}>
              {t("egress.openvpn.upload", { defaultValue: "Upload" })}
            </TabsTrigger>
            <TabsTrigger value="paste" disabled={isEditing}>
              {t("egress.openvpn.paste", { defaultValue: "Paste" })}
            </TabsTrigger>
            <TabsTrigger value="manual">
              {t("egress.openvpn.manual", { defaultValue: "Manual" })}
            </TabsTrigger>
          </TabsList>

          {/* Upload Tab */}
          <TabsContent value="upload" className="space-y-4">
            <div 
              className="border-2 border-dashed border-muted-foreground/25 rounded-lg p-8 text-center cursor-pointer hover:border-primary/50 transition-colors"
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload className="h-10 w-10 mx-auto mb-4 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                {t("egress.openvpn.uploadHint", { defaultValue: "Click to upload .ovpn or .conf file" })}
              </p>
              <input
                ref={fileInputRef}
                type="file"
                accept=".ovpn,.conf"
                className="hidden"
                onChange={handleFileUpload}
              />
            </div>
            {parseError && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{parseError}</AlertDescription>
              </Alert>
            )}
          </TabsContent>

          {/* Paste Tab */}
          <TabsContent value="paste" className="space-y-4">
            <Textarea
              value={pasteContent}
              onChange={(e) => setPasteContent(e.target.value)}
              placeholder={t("egress.openvpn.pasteHint", { defaultValue: "Paste OpenVPN config content here..." })}
              className="min-h-[200px] font-mono text-xs"
            />
            <Button onClick={handlePasteConfig} disabled={parseMutation.isPending}>
              {parseMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              <FileText className="mr-2 h-4 w-4" />
              {t("egress.openvpn.parseConfig", { defaultValue: "Parse Config" })}
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
                  placeholder="openvpn-server"
                  disabled={isEditing}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">{t("common.description", { defaultValue: "Description" })}</Label>
                <Input
                  id="description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="My OpenVPN Server"
                />
              </div>
            </div>

            {/* Connection */}
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label>{t("egress.openvpn.protocol", { defaultValue: "Protocol" })}</Label>
                <Select value={protocol} onValueChange={(v) => setProtocol(v as "udp" | "tcp")}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="udp">UDP</SelectItem>
                    <SelectItem value="tcp">TCP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="remoteHost">{t("egress.openvpn.remoteHost", { defaultValue: "Remote Host" })}</Label>
                <Input
                  id="remoteHost"
                  value={remoteHost}
                  onChange={(e) => setRemoteHost(e.target.value)}
                  placeholder="vpn.example.com"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="remotePort">{t("egress.openvpn.remotePort", { defaultValue: "Port" })}</Label>
                <Input
                  id="remotePort"
                  type="number"
                  value={remotePort}
                  onChange={(e) => setRemotePort(parseInt(e.target.value) || 1194)}
                />
              </div>
            </div>

            {/* Certificates */}
            <div className="space-y-2">
              <Label htmlFor="caCert">{t("egress.openvpn.caCert", { defaultValue: "CA Certificate" })} *</Label>
              <Textarea
                id="caCert"
                value={caCert}
                onChange={(e) => setCaCert(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----"
                className="font-mono text-xs min-h-[100px]"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="clientCert">{t("egress.openvpn.clientCert", { defaultValue: "Client Certificate" })}</Label>
                <Textarea
                  id="clientCert"
                  value={clientCert}
                  onChange={(e) => setClientCert(e.target.value)}
                  className="font-mono text-xs min-h-[80px]"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="clientKey">{t("egress.openvpn.clientKey", { defaultValue: "Client Key" })}</Label>
                <Textarea
                  id="clientKey"
                  value={clientKey}
                  onChange={(e) => setClientKey(e.target.value)}
                  className="font-mono text-xs min-h-[80px]"
                />
              </div>
            </div>

            {/* TLS Options */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="tlsAuth">{t("egress.openvpn.tlsAuth", { defaultValue: "TLS Auth Key" })}</Label>
                <Textarea
                  id="tlsAuth"
                  value={tlsAuth}
                  onChange={(e) => setTlsAuth(e.target.value)}
                  className="font-mono text-xs min-h-[60px]"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tlsCrypt">{t("egress.openvpn.tlsCrypt", { defaultValue: "TLS Crypt Key" })}</Label>
                <Textarea
                  id="tlsCrypt"
                  value={tlsCrypt}
                  onChange={(e) => setTlsCrypt(e.target.value)}
                  className="font-mono text-xs min-h-[60px]"
                />
              </div>
            </div>

            {/* Authentication */}
            <div ref={authFieldsRef} className={authValidationError ? "ring-2 ring-destructive rounded-lg p-2" : ""}>
              {showAuthHint && (
                <Alert className="mb-4">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    {t("egress.openvpn.authRequired", { 
                      defaultValue: "This config requires username/password authentication" 
                    })}
                  </AlertDescription>
                </Alert>
              )}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="authUser">{t("egress.openvpn.authUser", { defaultValue: "Username" })}</Label>
                  <Input
                    id="authUser"
                    value={authUser}
                    onChange={(e) => setAuthUser(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="authPass">{t("egress.openvpn.authPass", { defaultValue: "Password" })}</Label>
                  <Input
                    id="authPass"
                    type="password"
                    value={authPass}
                    onChange={(e) => setAuthPass(e.target.value)}
                  />
                </div>
              </div>
            </div>

            {/* Crypto Settings */}
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label>{t("egress.openvpn.cipher", { defaultValue: "Cipher" })}</Label>
                <Select value={cipher} onValueChange={setCipher}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CIPHER_OPTIONS.map((c) => (
                      <SelectItem key={c} value={c}>{c}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t("egress.openvpn.auth", { defaultValue: "Auth" })}</Label>
                <Select value={auth} onValueChange={setAuth}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {AUTH_OPTIONS.map((a) => (
                      <SelectItem key={a} value={a}>{a}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t("egress.openvpn.compress", { defaultValue: "Compression" })}</Label>
                <Select value={compress} onValueChange={setCompress}>
                  <SelectTrigger>
                    <SelectValue placeholder="None" />
                  </SelectTrigger>
                  <SelectContent>
                    {COMPRESS_OPTIONS.map((c) => (
                      <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={!tag.trim() || !remoteHost.trim() || !caCert.trim() || isSubmitting}
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
