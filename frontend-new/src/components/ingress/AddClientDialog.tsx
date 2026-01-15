import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAddIngressClient, useIngressOutbound } from "@/api/hooks/useIngress";
import { Loader2 } from "lucide-react";

const addClientSchema = z.object({
  name: z.string().min(1, "Name is required").regex(/^[a-zA-Z0-9_-]+$/, "Name can only contain letters, numbers, underscores and dashes"),
  publicKey: z.string().optional(),
  allowLan: z.boolean().default(false),
  defaultOutbound: z.string().optional(),
});

interface AddClientDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onClientCreated?: (name: string, privateKey?: string) => void;
}

interface AddClientForm {
  name: string;
  publicKey?: string;
  allowLan: boolean;
  defaultOutbound?: string;
}

export function AddClientDialog({ open, onOpenChange, onClientCreated }: AddClientDialogProps) {
  const { t } = useTranslation();
  const { mutate: addClient, isPending } = useAddIngressClient();
  const { data: outboundData } = useIngressOutbound();

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    watch,
    formState: { errors },
  } = useForm<AddClientForm>({
    resolver: zodResolver(addClientSchema) as any,
    defaultValues: {
      allowLan: false,
    },
  });

  const onSubmit = (data: AddClientForm) => {
    addClient(
      {
        name: data.name,
        publicKey: data.publicKey || undefined,
        allowLan: data.allowLan,
        defaultOutbound: data.defaultOutbound === "null" ? undefined : data.defaultOutbound,
      },
      {
        onSuccess: (response) => {
          reset();
          onOpenChange(false);
          if (onClientCreated) {
            // Pass the private key from the response if available
            onClientCreated(data.name, response.client_private_key);
          }
        },
      }
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("ingress.addClient")}</DialogTitle>
          <DialogDescription>{t("ingress.addClientDesc")}</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="name">{t("ingress.clientName")}</Label>
            <Input
              id="name"
              {...register("name")}
              placeholder={t("ingress.clientNamePlaceholder")}
            />
            {errors.name && (
              <p className="text-sm text-destructive">{errors.name.message}</p>
            )}
          </div>

          <div className="grid gap-2">
            <Label htmlFor="publicKey">{t("ingress.publicKey")}</Label>
            <Input
              id="publicKey"
              {...register("publicKey")}
              placeholder={t("ingress.autoGenerateKeyHint")}
            />
            {errors.publicKey && (
              <p className="text-sm text-destructive">{errors.publicKey.message}</p>
            )}
          </div>

          <div className="grid gap-2">
            <Label>{t("ingress.defaultOutbound")}</Label>
            <Select
              onValueChange={(value) => setValue("defaultOutbound", value)}
              defaultValue="null"
            >
              <SelectTrigger>
                <SelectValue placeholder={t("ingress.selectOutbound")} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="null">{t("ingress.globalDefault")}</SelectItem>
                {outboundData?.available_outbounds.map((outbound) => (
                  <SelectItem key={outbound} value={outbound}>
                    {outbound}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center space-x-2">
            <Checkbox
              id="allowLan"
              checked={watch("allowLan")}
              onCheckedChange={(checked) => setValue("allowLan", checked as boolean)}
            />
            <Label htmlFor="allowLan">{t("ingress.allowLanAccess")}</Label>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t("ingress.addClient")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
