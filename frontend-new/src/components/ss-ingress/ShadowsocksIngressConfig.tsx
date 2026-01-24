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
import { Loader2, Eye, EyeOff } from "lucide-react";
import { SHADOWSOCKS_METHODS, type ShadowsocksMethod } from "@/types";

// SS2022 methods require specific key lengths (in bytes)
const SS2022_KEY_LENGTHS: Record<string, number> = {
  "2022-blake3-aes-256-gcm": 32,
  "2022-blake3-aes-128-gcm": 16,
  "2022-blake3-chacha20-poly1305": 32,
};

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

export function ShadowsocksIngressConfig() {
  const { data: configData, isLoading: isLoadingConfig } = useShadowsocksIngressConfig();
  const { mutate: updateConfig, isPending: isUpdatingConfig } = useUpdateShadowsocksIngressConfig();

  const { data: outboundData, isLoading: isLoadingOutbound } = useShadowsocksIngressOutbound();
  const { mutate: setOutbound, isPending: isSettingOutbound } = useSetShadowsocksIngressOutbound();

  const [showPassword, setShowPassword] = useState(false);
  const [keyValidationError, setKeyValidationError] = useState<string | null>(null);

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
      setValue("listen_addr", configData.config.listen_addr);
      setValue("listen_port", configData.config.listen_port);
      setValue("method", configData.config.method);
      // Password is typically not returned for security
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
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="Leave blank to keep existing password"
                  {...register("password")}
                  className="pr-10"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4 text-muted-foreground" />
                  ) : (
                    <Eye className="h-4 w-4 text-muted-foreground" />
                  )}
                  <span className="sr-only">
                    {showPassword ? "Hide password" : "Show password"}
                  </span>
                </Button>
              </div>
              {keyValidationError && (
                <p className="text-sm text-destructive">{keyValidationError}</p>
              )}
              <p className="text-xs text-muted-foreground">
                Enter a new password to update, or leave blank to keep the existing one
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
    </div>
  );
}
