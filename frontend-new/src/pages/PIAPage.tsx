import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { usePIAStatus, usePIALogin, usePIARegions, useAddPIALine } from "@/api/hooks/usePIA";
import { Loader2, CheckCircle2, XCircle, Plus } from "lucide-react";
import { useNavigate } from "react-router-dom";

const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

const addLineSchema = z.object({
  tag: z.string().min(1, "Tag is required").regex(/^[a-zA-Z0-9_-]+$/, "Tag can only contain letters, numbers, underscores and dashes"),
  description: z.string().min(1, "Description is required"),
  regionId: z.string().min(1, "Region is required"),
  customDns: z.string().optional(),
});

export default function PIAPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { data: status, isLoading: isLoadingStatus } = usePIAStatus();
  const { data: regionsData, isLoading: isLoadingRegions } = usePIARegions();
  const { mutate: login, isPending: isLoggingIn } = usePIALogin();
  const { mutate: addLine, isPending: isAddingLine } = useAddPIALine();

  const {
    register: registerLogin,
    handleSubmit: handleSubmitLogin,
    formState: { errors: loginErrors },
  } = useForm<{ username: string; password: string }>({
    resolver: zodResolver(loginSchema),
  });

  const {
    register: registerAdd,
    handleSubmit: handleSubmitAdd,
    setValue: setAddValue,
    reset: resetAdd,
    formState: { errors: addErrors },
  } = useForm<{ tag: string; description: string; regionId: string; customDns?: string }>({
    resolver: zodResolver(addLineSchema),
  });

  const onLogin = (data: { username: string; password: string }) => {
    login(data);
  };

  const onAddLine = (data: { tag: string; description: string; regionId: string; customDns?: string }) => {
    addLine(data, {
      onSuccess: () => {
        resetAdd();
        navigate("/egress");
      },
    });
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
          <h1 className="text-3xl font-bold tracking-tight">{t("pia.title")}</h1>
          <p className="text-muted-foreground">{t("pia.subtitle")}</p>
        </div>


      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{t("pia.credentialStatus")}</CardTitle>
            <CardDescription>{t("pia.credentialStatusDesc")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-2 p-4 border rounded-lg bg-muted/50">
              {status?.has_credentials ? (
                <>
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                  <div className="flex-1">
                    <p className="font-medium">{t("pia.hasCredentials")}</p>
                    <p className="text-sm text-muted-foreground">{status.message}</p>
                  </div>
                </>
              ) : (
                <>
                  <XCircle className="h-5 w-5 text-destructive" />
                  <div className="flex-1">
                    <p className="font-medium">{t("pia.noCredentials")}</p>
                    <p className="text-sm text-muted-foreground">{t("pia.enterCredentials")}</p>
                  </div>
                </>
              )}
            </div>

            <form onSubmit={handleSubmitLogin(onLogin)} className="space-y-4 mt-4">
              <div className="grid gap-2">
                <Label htmlFor="username">{t("pia.username")}</Label>
                <Input
                  id="username"
                  placeholder={t("pia.usernamePlaceholder")}
                  {...registerLogin("username")}
                />
                {loginErrors.username && (
                  <p className="text-sm text-destructive">{loginErrors.username.message}</p>
                )}
              </div>
              <div className="grid gap-2">
                <Label htmlFor="password">{t("pia.password")}</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder={t("pia.passwordPlaceholder")}
                  {...registerLogin("password")}
                />
                {loginErrors.password && (
                  <p className="text-sm text-destructive">{loginErrors.password.message}</p>
                )}
              </div>
              <Button type="submit" className="w-full" disabled={isLoggingIn}>
                {isLoggingIn && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {status?.has_credentials ? t("pia.updateCredentials") : t("pia.login")}
              </Button>
            </form>
          </CardContent>
        </Card>

        {status?.has_credentials && (
          <Card>
            <CardHeader>
              <CardTitle>{t("egress.addPiaLine")}</CardTitle>
              <CardDescription>{t("pia.addConnectionDescription")}</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmitAdd(onAddLine)} className="space-y-4">
                <div className="grid gap-2">
                  <Label htmlFor="tag">{t("egress.lineTag")}</Label>
                  <Input
                    id="tag"
                    placeholder={t("egress.lineTagPlaceholder")}
                    {...registerAdd("tag")}
                  />
                  {addErrors.tag && (
                    <p className="text-sm text-destructive">{addErrors.tag.message}</p>
                  )}
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="description">{t("common.description")}</Label>
                  <Input
                    id="description"
                    placeholder={t("egress.descriptionPlaceholder")}
                    {...registerAdd("description")}
                  />
                  {addErrors.description && (
                    <p className="text-sm text-destructive">{addErrors.description.message}</p>
                  )}
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="region">{t("egress.region")}</Label>
                  <Select onValueChange={(value) => setAddValue("regionId", value)}>
                    <SelectTrigger>
                      <SelectValue placeholder={t("egress.selectRegion")} />
                    </SelectTrigger>
                    <SelectContent className="max-h-[300px]">
                      {isLoadingRegions ? (
                        <div className="flex items-center justify-center p-2">
                          <Loader2 className="h-4 w-4 animate-spin" />
                        </div>
                      ) : (
                        regionsData?.regions.map((region) => (
                          <SelectItem key={region.id} value={region.id}>
                            {region.name} ({region.country}) {region.port_forward && "⚡"}
                          </SelectItem>
                        ))
                      )}
                    </SelectContent>
                  </Select>
                  {addErrors.regionId && (
                    <p className="text-sm text-destructive">{addErrors.regionId.message}</p>
                  )}
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="customDns">{t("egress.customDns")}</Label>
                  <Input
                    id="customDns"
                    placeholder={t("egress.customDnsPlaceholder")}
                    {...registerAdd("customDns")}
                  />
                </div>

                <Button type="submit" className="w-full" disabled={isAddingLine}>
                  {isAddingLine ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
                  {t("egress.addLine")}
                </Button>
              </form>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
