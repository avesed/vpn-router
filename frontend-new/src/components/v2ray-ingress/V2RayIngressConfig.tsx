import { useEffect } from "react";
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
  useV2RayIngressConfig,
  useUpdateV2RayIngressConfig,
  useGenerateRealityKeys,
  useV2RayIngressOutbound,
  useSetV2RayIngressOutbound,
} from "@/api/hooks/useV2RayIngress";
import { Loader2, RefreshCw, Save } from "lucide-react";
import { type V2RayProtocol, type V2RayTransport, V2RAY_PROTOCOLS, V2RAY_TRANSPORTS } from "@/types";

const configSchema = z.object({
  enabled: z.boolean(),
  protocol: z.enum(["vless", "vmess", "trojan"]),
  listen_port: z.number().min(1).max(65535),
  transport_type: z.enum(["tcp", "ws", "grpc", "h2", "quic", "httpupgrade", "xhttp"]),
  tls_enabled: z.boolean(),
  reality_enabled: z.boolean(),
  reality_private_key: z.string().optional(),
  reality_public_key: z.string().optional(),
  reality_dest: z.string().optional(),
  reality_server_names: z.string().optional(),
});

type ConfigFormValues = z.infer<typeof configSchema>;

export function V2RayIngressConfig() {
  const { data: config, isLoading: isLoadingConfig } = useV2RayIngressConfig();
  const { mutate: updateConfig, isPending: isUpdatingConfig } = useUpdateV2RayIngressConfig();
  const { mutate: generateKeys, isPending: isGeneratingKeys } = useGenerateRealityKeys();
  
  const { data: outboundData, isLoading: isLoadingOutbound } = useV2RayIngressOutbound();
  const { mutate: setOutbound, isPending: isSettingOutbound } = useSetV2RayIngressOutbound();

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
      protocol: "vless",
      transport_type: "tcp",
      tls_enabled: false,
      reality_enabled: false,
    },
  });

  const watchProtocol = watch("protocol");
  const watchTlsEnabled = watch("tls_enabled");
  const watchRealityEnabled = watch("reality_enabled");

  useEffect(() => {
    if (config?.config) {
      setValue("enabled", !!config.config.enabled);
      setValue("protocol", config.config.protocol);
      setValue("listen_port", config.config.listen_port);
      setValue("transport_type", config.config.transport_type);
      setValue("tls_enabled", !!config.config.tls_enabled);
      setValue("reality_enabled", !!config.config.reality_enabled);
      setValue("reality_private_key", config.config.reality_private_key);
      setValue("reality_public_key", config.config.reality_public_key);
      setValue("reality_dest", config.config.reality_dest);
      setValue(
        "reality_server_names",
        config.config.reality_server_names?.join(", ") || ""
      );
    }
  }, [config, setValue]);

  const onSubmit = (data: ConfigFormValues) => {
    updateConfig({
      enabled: data.enabled,
      protocol: data.protocol,
      listen_port: data.listen_port,
      transport_type: data.transport_type,
      tls_enabled: data.tls_enabled,
      reality_enabled: data.reality_enabled,
      reality_private_key: data.reality_private_key,
      reality_public_key: data.reality_public_key,
      reality_dest: data.reality_dest,
      reality_server_names: data.reality_server_names
        ? data.reality_server_names.split(",").map((s) => s.trim()).filter(Boolean)
        : [],
    });
  };

  const handleGenerateKeys = () => {
    generateKeys(undefined, {
      onSuccess: (keys) => {
        setValue("reality_private_key", keys.private_key);
        setValue("reality_public_key", keys.public_key);
      },
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
          <CardTitle>V2Ray Server Settings</CardTitle>
          <CardDescription>Configure V2Ray/Xray inbound settings</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="flex items-center space-x-2">
              <Switch
                id="enabled"
                checked={watch("enabled")}
                onCheckedChange={(checked) => setValue("enabled", checked)}
              />
              <Label htmlFor="enabled">Enable V2Ray Ingress</Label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>Protocol</Label>
                <Select
                  value={watchProtocol}
                  onValueChange={(value) => setValue("protocol", value as V2RayProtocol)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select protocol" />
                  </SelectTrigger>
                  <SelectContent>
                    {V2RAY_PROTOCOLS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-2">
                <Label>Transport</Label>
                <Select
                  value={watch("transport_type")}
                  onValueChange={(value) => setValue("transport_type", value as V2RayTransport)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select transport" />
                  </SelectTrigger>
                  <SelectContent>
                    {V2RAY_TRANSPORTS.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
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

            <div className="space-y-4 pt-4 border-t">
              <div className="flex items-center space-x-2">
                <Switch
                  id="tls_enabled"
                  checked={watchTlsEnabled}
                  onCheckedChange={(checked) => setValue("tls_enabled", checked)}
                />
                <Label htmlFor="tls_enabled">Enable TLS</Label>
              </div>

              {watchProtocol === "vless" && (
                <div className="flex items-center space-x-2">
                  <Switch
                    id="reality_enabled"
                    checked={watchRealityEnabled}
                    onCheckedChange={(checked) => setValue("reality_enabled", checked)}
                  />
                  <Label htmlFor="reality_enabled">Enable REALITY</Label>
                </div>
              )}

              {watchRealityEnabled && (
                <div className="space-y-4 p-4 border rounded-md bg-muted/50">
                  <div className="grid gap-2">
                    <Label>REALITY Keys</Label>
                    <div className="flex gap-2">
                      <div className="grid gap-2 flex-1">
                        <Input
                          placeholder="Private Key"
                          {...register("reality_private_key")}
                        />
                        <Input
                          placeholder="Public Key"
                          {...register("reality_public_key")}
                          readOnly
                        />
                      </div>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={handleGenerateKeys}
                        disabled={isGeneratingKeys}
                      >
                        {isGeneratingKeys ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <RefreshCw className="h-4 w-4" />
                        )}
                        <span className="sr-only">Generate Keys</span>
                      </Button>
                    </div>
                  </div>

                  <div className="grid gap-2">
                    <Label htmlFor="reality_dest">Target Destination (SNI:Port)</Label>
                    <Input
                      id="reality_dest"
                      placeholder="www.microsoft.com:443"
                      {...register("reality_dest")}
                    />
                  </div>

                  <div className="grid gap-2">
                    <Label htmlFor="reality_server_names">Server Names (comma separated)</Label>
                    <Input
                      id="reality_server_names"
                      placeholder="www.microsoft.com, microsoft.com"
                      {...register("reality_server_names")}
                    />
                  </div>
                </div>
              )}
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
            Choose which outbound interface V2Ray clients should use by default
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
            <Button disabled={isSettingOutbound} onClick={() => {}}>
              {isSettingOutbound ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              <span className="ml-2">Saved automatically</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
