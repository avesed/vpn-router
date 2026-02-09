import { useEffect } from "react";
import { useTranslation } from "react-i18next";
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
  const { t } = useTranslation();
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
          <CardTitle>{t("ingress.serverSettings")}</CardTitle>
          <CardDescription>{t("ingress.serverSettingsDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmitSettings(onSettingsSubmit)} className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="serverEndpoint">{t("ingress.serverPublicAddress")}</Label>
              <div className="flex gap-2">
                <Input
                  id="serverEndpoint"
                  {...registerSettings("serverEndpoint")}
                  placeholder={t("ingress.serverAddressPlaceholder")}
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
                  <span className="sr-only">{t("ingress.autoDetect")}</span>
                </Button>
              </div>
              {settingsErrors.serverEndpoint && (
                <p className="text-sm text-destructive">{settingsErrors.serverEndpoint.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label>{t("ingress.listenPort")}</Label>
              <Input value={settings?.listen_port} disabled />
              <p className="text-xs text-muted-foreground">
                {t("ingress.listenPortHint")}
              </p>
            </div>

            <Button type="submit" disabled={isUpdatingSettings}>
              {isUpdatingSettings && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t("common.save")}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("ingress.subnetConfigTitle")}</CardTitle>
          <CardDescription>{t("ingress.subnetConfigDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmitSubnet(onSubnetSubmit)} className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="subnetAddress">{t("ingress.subnetAddress")}</Label>
              <Input
                id="subnetAddress"
                {...registerSubnet("address")}
                placeholder={t("ingress.subnetAddressPlaceholder")}
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
              <Label htmlFor="migratePeers">{t("ingress.migratePeers")}</Label>
            </div>

            {subnet?.conflicts && subnet.conflicts.length > 0 && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>{t("ingress.subnetConflictWarning")}</AlertTitle>
                <AlertDescription>
                  <ul className="list-disc pl-4 mt-2">
                    {subnet.conflicts.map((conflict, i) => (
                      <li key={i}>
                        {t("ingress.subnetConflictItem", {
                          address: conflict.address,
                          type: conflict.type,
                          tag: conflict.tag,
                        })}
                      </li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}

            <Button type="submit" disabled={isUpdatingSubnet}>
              {isUpdatingSubnet && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t("common.save")}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("ingress.defaultOutbound")}</CardTitle>
          <CardDescription>{t("ingress.defaultOutboundHint")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-4">
            <div className="grid gap-2 flex-1">
              <Label>{t("rules.outbound")}</Label>
              <Select
                value={outboundData?.outbound || "null"}
                onValueChange={(value) => setOutbound(value === "null" ? null : value)}
                disabled={isSettingOutbound}
              >
                <SelectTrigger>
                  <SelectValue placeholder={t("ingress.selectOutbound")} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="null">
                    {t("ingress.globalDefault")} ({outboundData?.global_default})
                  </SelectItem>
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
              <span className="ml-2">{t("ingress.autoSaved")}</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
