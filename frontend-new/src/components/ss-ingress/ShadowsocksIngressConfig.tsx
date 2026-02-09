import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  useShadowsocksIngressConfig,
  useUpdateShadowsocksIngressConfig,
  useShadowsocksIngressOutbound,
  useSetShadowsocksIngressOutbound,
} from "@/api/hooks/useShadowsocksIngress";
import { Loader2, RefreshCw, Copy, Check } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { SHADOWSOCKS_METHODS, type ShadowsocksMethod } from "@/types";

// SS2022 methods require specific key lengths (in bytes)
const SS2022_KEY_LENGTHS: Record<string, number> = {
  "2022-blake3-aes-256-gcm": 32,
  "2022-blake3-aes-128-gcm": 16,
  "2022-blake3-chacha20-poly1305": 32,
};

// Default key lengths for legacy AEAD methods (recommended, but not strict)
const LEGACY_AEAD_KEY_LENGTH = 32;

/**
 * Generate a cryptographically secure random key for Shadowsocks.
 * - SS2022 methods: generates Base64-encoded key of exact required length
 * - Legacy AEAD methods: generates a random 32-byte Base64 key (will be derived via HKDF)
 */
function generateKey(method: string): string {
  const keyLength = SS2022_KEY_LENGTHS[method] || LEGACY_AEAD_KEY_LENGTH;
  const randomBytes = new Uint8Array(keyLength);
  crypto.getRandomValues(randomBytes);

  // Convert to Base64
  let binary = "";
  randomBytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

// Validate base64 key length for SS2022 methods
function validateSS2022Key(password: string, method: string): string | null {
  const requiredLength = SS2022_KEY_LENGTHS[method];
  if (!requiredLength) return null; // Not SS2022 method

  try {
    // Check if it's valid base64
    const decoded = atob(password);
    if (decoded.length !== requiredLength) {
      return `Key must be ${requiredLength} bytes (base64 encoded: ${Math.ceil(requiredLength * 4 / 3)} chars)`;
    }
    return null;
  } catch {
    return "Invalid base64 encoding";
  }
}

const configSchema = z.object({
  enabled: z.boolean(),
  listen_addr: z.string().min(1, "Listen address is required"),
  listen_port: z.number().min(1).max(65535),
  method: z.string().min(1, "Encryption method is required"),
  password: z.string().optional(),
  udp_enabled: z.boolean(),
});

type ConfigFormValues = z.infer<typeof configSchema>;

/**
 * Generate Shadowsocks URL (SIP002 format)
 * Format: ss://BASE64(method:password)@host:port#tag
 */
function generateSsUrl(method: string, password: string, host: string, port: number, tag?: string): string {
  // SIP002 format uses userinfo encoding
  const userinfo = btoa(`${method}:${password}`);
  const baseUrl = `ss://${userinfo}@${host}:${port}`;
  if (tag) {
    return `${baseUrl}#${encodeURIComponent(tag)}`;
  }
  return baseUrl;
}

export function ShadowsocksIngressConfig() {
  const { data: configData, isLoading: isLoadingConfig } = useShadowsocksIngressConfig();
  const { mutate: updateConfig, isPending: isUpdatingConfig } = useUpdateShadowsocksIngressConfig();

  const { data: outboundData, isLoading: isLoadingOutbound } = useShadowsocksIngressOutbound();
  const { mutate: setOutbound, isPending: isSettingOutbound } = useSetShadowsocksIngressOutbound();

  const [keyValidationError, setKeyValidationError] = useState<string | null>(null);
  const [copiedUrl, setCopiedUrl] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
  } = useForm<ConfigFormValues>({
    resolver: zodResolver(configSchema),
    defaultValues: {
      enabled: false,
      listen_addr: "0.0.0.0",
      listen_port: 8388,
      method: "2022-blake3-aes-256-gcm",
      password: "",
      udp_enabled: true,
    },
  });

  const watchEnabled = watch("enabled");
  const watchMethod = watch("method");

  useEffect(() => {
    if (configData?.config) {
      setValue("enabled", configData.config.enabled);
      setValue("listen_addr", configData.config.listen_addr || "0.0.0.0");
      setValue("listen_port", configData.config.listen_port || 8388);
      // Ensure method has a valid value from SHADOWSOCKS_METHODS
      const method = configData.config.method;
      const validMethod = SHADOWSOCKS_METHODS.find(m => m.value === method);
      setValue("method", validMethod ? method : "2022-blake3-aes-256-gcm");
      // Set password if returned from API
      if (configData.config.password) {
        setValue("password", configData.config.password);
      }
      setValue("udp_enabled", configData.config.udp_enabled);
    }
  }, [configData, setValue]);

  const onSubmit = (data: ConfigFormValues) => {
    // Validate SS2022 key if password is provided
    if (data.password && SS2022_KEY_LENGTHS[data.method]) {
      const validationError = validateSS2022Key(data.password, data.method);
      if (validationError) {
        setKeyValidationError(validationError);
        return;
      }
    }
    setKeyValidationError(null);

    updateConfig({
      enabled: data.enabled,
      listen_addr: data.listen_addr,
      listen_port: data.listen_port,
      method: data.method,
      password: data.password || undefined,
      udp_enabled: data.udp_enabled,
    });
  };

  if (isLoadingConfig || isLoadingOutbound) {
    return (
      <Card>
        <CardContent className="pt-6 flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Shadowsocks Server Settings</CardTitle>
          <CardDescription>Configure Shadowsocks inbound settings for incoming connections</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="flex items-center space-x-2">
              <Switch
                id="enabled"
                checked={watchEnabled}
                onCheckedChange={(checked) => setValue("enabled", checked)}
              />
              <Label htmlFor="enabled">Enable Shadowsocks Ingress</Label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="listen_addr">Listen Address</Label>
                <Input
                  id="listen_addr"
                  placeholder="0.0.0.0"
                  {...register("listen_addr")}
                />
                {errors.listen_addr && (
                  <p className="text-sm text-destructive">{errors.listen_addr.message}</p>
                )}
              </div>

              <div className="grid gap-2">
                <Label htmlFor="listen_port">Listen Port</Label>
                <Input
                  id="listen_port"
                  type="number"
                  {...register("listen_port", { valueAsNumber: true })}
                />
                {errors.listen_port && (
                  <p className="text-sm text-destructive">{errors.listen_port.message}</p>
                )}
              </div>
            </div>

            <div className="grid gap-2">
              <Label>Encryption Method</Label>
              <Select
                value={watchMethod}
                onValueChange={(value) => setValue("method", value as ShadowsocksMethod)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select encryption method" />
                </SelectTrigger>
                <SelectContent>
                  {SHADOWSOCKS_METHODS.map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {watchMethod?.startsWith("2022-") && (
                <p className="text-xs text-muted-foreground">
                  SS2022 methods require a base64-encoded key of the correct length
                </p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="password">Password / Key</Label>
              <div className="flex gap-2">
                <Input
                  id="password"
                  type="text"
                  placeholder="Leave blank to keep existing password"
                  {...register("password")}
                  className="flex-1 font-mono text-sm"
                />
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        onClick={() => {
                          const newKey = generateKey(watchMethod);
                          setValue("password", newKey);
                          setKeyValidationError(null);
                        }}
                      >
                        <RefreshCw className="h-4 w-4" />
                        <span className="sr-only">Generate key</span>
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>Generate random key ({SS2022_KEY_LENGTHS[watchMethod] || LEGACY_AEAD_KEY_LENGTH} bytes)</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
              {keyValidationError && (
                <p className="text-sm text-destructive">{keyValidationError}</p>
              )}
              <p className="text-xs text-muted-foreground">
                {watchMethod?.startsWith("2022-")
                  ? `SS2022 requires a ${SS2022_KEY_LENGTHS[watchMethod]}-byte base64 key. Click the refresh button to generate one.`
                  : "Enter a password or click the refresh button to generate a random key."}
              </p>
            </div>

            {/* UDP Support */}
            <div className="space-y-4 pt-4 border-t">
              <div className="flex items-center space-x-2">
                <Switch
                  id="udp_enabled"
                  checked={watch("udp_enabled")}
                  onCheckedChange={(checked) => setValue("udp_enabled", checked)}
                />
                <Label htmlFor="udp_enabled">Enable UDP Support</Label>
                <span className="text-xs text-muted-foreground ml-2">
                  (Required for UDP relay, DNS over UDP)
                </span>
              </div>
            </div>

            <Button type="submit" disabled={isUpdatingConfig}>
              {isUpdatingConfig && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save Configuration
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Default Outbound</CardTitle>
          <CardDescription>
            Choose which outbound interface Shadowsocks clients should use by default
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-4">
            <div className="grid gap-2 flex-1">
              <Label>Outbound Interface</Label>
              <Select
                value={outboundData?.outbound || "null"}
                onValueChange={(value) => setOutbound(value === "null" ? null : value)}
                disabled={isSettingOutbound}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select outbound..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="null">Global Default ({outboundData?.global_default})</SelectItem>
                  {outboundData?.available_outbounds.map((outbound) => (
                    <SelectItem key={outbound} value={outbound}>
                      {outbound}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {isSettingOutbound && (
              <div className="flex items-center text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                <span className="text-sm">Saving...</span>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Quick Connect URL - show when password exists (from form or saved config) */}
      {(watch("password") || configData?.config?.password) && (
        <Card>
          <CardHeader>
            <CardTitle>Quick Connect</CardTitle>
            <CardDescription>
              Use this URL to connect from Shadowsocks clients
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!watchEnabled && (
              <div className="text-sm text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/30 p-3 rounded-md">
                ⚠️ Shadowsocks ingress is currently disabled. Enable it and save to accept connections.
              </div>
            )}
            <div className="grid gap-2">
              <Label>Connection URL</Label>
              <div className="flex gap-2">
                <Input
                  readOnly
                  value={generateSsUrl(
                    watchMethod || configData?.config?.method || "2022-blake3-aes-256-gcm",
                    watch("password") || configData?.config?.password || "",
                    window.location.hostname,
                    watch("listen_port") || configData?.config?.listen_port || 8388,
                    "VPN-Gateway-SS"
                  )}
                  className="font-mono text-xs flex-1"
                />
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        onClick={() => {
                          const url = generateSsUrl(
                            watchMethod || configData?.config?.method || "2022-blake3-aes-256-gcm",
                            watch("password") || configData?.config?.password || "",
                            window.location.hostname,
                            watch("listen_port") || configData?.config?.listen_port || 8388,
                            "VPN-Gateway-SS"
                          );
                          navigator.clipboard.writeText(url);
                          setCopiedUrl(true);
                          setTimeout(() => setCopiedUrl(false), 2000);
                        }}
                      >
                        {copiedUrl ? (
                          <Check className="h-4 w-4 text-green-500" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                        <span className="sr-only">Copy URL</span>
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>{copiedUrl ? "Copied!" : "Copy to clipboard"}</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
              <p className="text-xs text-muted-foreground">
                Import this URL in your Shadowsocks client (Clash, Shadowrocket, etc.)
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
