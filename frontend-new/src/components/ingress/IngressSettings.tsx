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
  useIngressSettings,
  useUpdateIngressSettings,
  useIngressSubnet,
  useUpdateIngressSubnet,
  useDetectIp,
  useIngressOutbound,
  useSetIngressOutbound,
} from "@/api/hooks/useIngress";
import { Loader2, RefreshCw, Save, AlertTriangle } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const settingsSchema = z.object({
  serverEndpoint: z.string().min(1, "Server endpoint is required"),
});

const subnetSchema = z.object({
  address: z.string().regex(/^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/, "Invalid CIDR format"),
  migratePeers: z.boolean().default(true),
});

interface SubnetForm {
  address: string;
  migratePeers: boolean;
}

export function IngressSettings() {
  const { data: settings, isLoading: isLoadingSettings } = useIngressSettings();
  const { mutate: updateSettings, isPending: isUpdatingSettings } = useUpdateIngressSettings();
  const { mutate: detectIp, isPending: isDetectingIp } = useDetectIp();
  
  const { data: subnet, isLoading: isLoadingSubnet } = useIngressSubnet();
  const { mutate: updateSubnet, isPending: isUpdatingSubnet } = useUpdateIngressSubnet();

  const { data: outboundData, isLoading: isLoadingOutbound } = useIngressOutbound();
  const { mutate: setOutbound, isPending: isSettingOutbound } = useSetIngressOutbound();

  const {
    register: registerSettings,
    handleSubmit: handleSubmitSettings,
    setValue: setSettingsValue,
    formState: { errors: settingsErrors },
  } = useForm<{ serverEndpoint: string }>({
    resolver: zodResolver(settingsSchema),
  });

  const {
    register: registerSubnet,
    handleSubmit: handleSubmitSubnet,
    setValue: setSubnetValue,
    watch: watchSubnet,
    formState: { errors: subnetErrors },
  } = useForm<SubnetForm>({
    resolver: zodResolver(subnetSchema) as any,
    defaultValues: {
      migratePeers: true,
    },
  });

  useEffect(() => {
    if (settings) {
      setSettingsValue("serverEndpoint", settings.server_endpoint);
    }
  }, [settings, setSettingsValue]);

  useEffect(() => {
    if (subnet) {
      setSubnetValue("address", subnet.address);
    }
  }, [subnet, setSubnetValue]);

  const onSettingsSubmit = (data: { serverEndpoint: string }) => {
    updateSettings(data.serverEndpoint);
  };

  const onSubnetSubmit = (data: SubnetForm) => {
    updateSubnet(data);
  };

  const handleDetectIp = () => {
    detectIp(undefined, {
      onSuccess: (data) => {
        if (data.public_ip) {
          setSettingsValue("serverEndpoint", data.public_ip);
        }
      },
    });
  };

  if (isLoadingSettings || isLoadingSubnet || isLoadingOutbound) {
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
          <CardTitle>Server Settings</CardTitle>
          <CardDescription>Configure WireGuard server endpoint and port</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmitSettings(onSettingsSubmit)} className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="serverEndpoint">Server Endpoint (Public IP/Domain)</Label>
              <div className="flex gap-2">
                <Input
                  id="serverEndpoint"
                  {...registerSettings("serverEndpoint")}
                  placeholder="e.g. 203.0.113.1"
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleDetectIp}
                  disabled={isDetectingIp}
                >
                  {isDetectingIp ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4" />
                  )}
                  <span className="sr-only">Detect IP</span>
                </Button>
              </div>
              {settingsErrors.serverEndpoint && (
                <p className="text-sm text-destructive">{settingsErrors.serverEndpoint.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label>Listen Port</Label>
              <Input value={settings?.listen_port} disabled />
              <p className="text-xs text-muted-foreground">
                Port is managed by the system configuration
              </p>
            </div>

            <Button type="submit" disabled={isUpdatingSettings}>
              {isUpdatingSettings && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save Settings
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Subnet Configuration</CardTitle>
          <CardDescription>Configure the internal subnet for WireGuard clients</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmitSubnet(onSubnetSubmit)} className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="subnetAddress">Subnet Address (CIDR)</Label>
              <Input
                id="subnetAddress"
                {...registerSubnet("address")}
                placeholder="e.g. 10.10.0.1/24"
              />
              {subnetErrors.address && (
                <p className="text-sm text-destructive">{subnetErrors.address.message}</p>
              )}
            </div>

            <div className="flex items-center space-x-2">
              <Switch
                id="migratePeers"
                checked={watchSubnet("migratePeers")}
                onCheckedChange={(checked) => setSubnetValue("migratePeers", checked)}
              />
              <Label htmlFor="migratePeers">Migrate existing peers to new subnet</Label>
            </div>

            {subnet?.conflicts && subnet.conflicts.length > 0 && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>IP Conflicts Detected</AlertTitle>
                <AlertDescription>
                  <ul className="list-disc pl-4 mt-2">
                    {subnet.conflicts.map((conflict, i) => (
                      <li key={i}>
                        {conflict.address} used by {conflict.type} ({conflict.tag})
                      </li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}

            <Button type="submit" disabled={isUpdatingSubnet}>
              {isUpdatingSubnet && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Update Subnet
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Default Outbound</CardTitle>
          <CardDescription>
            Choose which outbound interface WireGuard clients should use by default
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
