import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Loader2, CheckCircle } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Textarea } from "@/components/ui/textarea";
import { useCompletePairing } from "@/api/hooks/usePairing";

const formSchema = z.object({
  code: z.string().min(1, "Response code is required"),
});

type FormValues = z.infer<typeof formSchema>;

interface CompletePairingDialogProps {
  trigger?: React.ReactNode;
}

export function CompletePairingDialog({ trigger }: CompletePairingDialogProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<{ 
    success: boolean; 
    message: string;
    created_node_tag: string | null;
  } | null>(null);

  const completePairing = useCompletePairing();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any,
    defaultValues: {
      code: "",
    },
  });

  const onSubmit = (data: FormValues) => {
    // The response code contains all the information needed
    // We pass an empty pending_request as the server will look it up
    completePairing.mutate({
      code: data.code,
      pending_request: {},
    }, {
      onSuccess: (response) => {
        setResult({
          success: response.success,
          message: response.message,
          created_node_tag: response.created_node_tag,
        });
        if (response.success) {
          toast.success(response.message);
        }
      },
    });
  };

  const reset = () => {
    setResult(null);
    form.reset();
  };

  return (
    <Dialog open={open} onOpenChange={(val) => {
      setOpen(val);
      if (!val) reset();
    }}>
      <DialogTrigger asChild>
        {trigger || (
          <Button variant="outline">{t("pairing.completeButton")}</Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>{t("pairing.completeTitle")}</DialogTitle>
          <DialogDescription>{t("pairing.completeDescription")}</DialogDescription>
        </DialogHeader>

        {!result ? (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="code"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t("pairing.responseCode")}</FormLabel>
                    <FormControl>
                      <Textarea 
                        placeholder={t("pairing.responseCodePlaceholder")}
                        className="resize-none font-mono text-xs"
                        rows={4}
                        {...field} 
                      />
                    </FormControl>
                    <FormDescription>
                      {t("pairing.completeHint")}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button 
                type="submit" 
                className="w-full" 
                disabled={completePairing.isPending}
              >
                {completePairing.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                {t("pairing.completeSubmit")}
              </Button>
            </form>
          </Form>
        ) : (
          <div className="space-y-4">
            {result.success ? (
              <div className="rounded-md bg-green-50 p-4 dark:bg-green-900/20">
                <div className="flex items-center gap-3">
                  <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
                  <div>
                    <p className="text-sm font-medium text-green-700 dark:text-green-400">
                      {result.message}
                    </p>
                    {result.created_node_tag && (
                      <p className="text-sm text-green-600 dark:text-green-500 mt-1">
                        {t("pairing.createdNode")}: {result.created_node_tag}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-md bg-red-50 p-4 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-400">
                {result.message}
              </div>
            )}

            <Button variant="outline" className="w-full" onClick={() => setOpen(false)}>
              {t("common.close")}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
