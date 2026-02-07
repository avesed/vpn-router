import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/providers/AuthProvider";
import { api } from "@/api/client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Hourglass, RefreshCw, Loader2, LogOut, CheckCircle, Languages } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function PendingPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const { pendingUser, pendingCredentials, clearPending, isPending, isAuthenticated } = useAuth();

  const [checking, setChecking] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "info" | "error"; text: string } | null>(null);

  // If not pending and authenticated, redirect to dashboard
  useEffect(() => {
    if (!isPending && isAuthenticated) {
      navigate("/");
    }
  }, [isPending, isAuthenticated, navigate]);

  // If not pending and not authenticated, redirect to login
  useEffect(() => {
    if (!isPending && !isAuthenticated) {
      navigate("/login");
    }
  }, [isPending, isAuthenticated, navigate]);

  const checkStatus = async () => {
    if (!pendingCredentials) {
      // No stored credentials, must re-login
      clearPending();
      navigate("/login");
      return;
    }

    setChecking(true);
    setStatusMessage(null);

    try {
      const result = await api.checkPendingStatus({
        username: pendingCredentials.username,
        password: pendingCredentials.password
      });

      if (result.status === "approved") {
        setStatusMessage({ type: "success", text: t("auth.statusApproved") });
        // Clear pending state and redirect to login after a short delay
        setTimeout(() => {
          clearPending();
          navigate("/login");
        }, 2000);
      } else {
        setStatusMessage({ type: "info", text: t("auth.statusStillPending") });
      }
    } catch (error) {
      setStatusMessage({
        type: "error",
        text: error instanceof Error ? error.message : t("auth.checkStatusError")
      });
    } finally {
      setChecking(false);
    }
  };

  const handleReturnToLogin = () => {
    clearPending();
    navigate("/login");
  };

  // Don't render if not pending
  if (!isPending) {
    return null;
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background">
      <div className="absolute top-4 right-4">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm">
              <Languages className="mr-2 h-4 w-4" />
              {t("language.title")}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => i18n.changeLanguage("en")}>
              {t("language.en")}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => i18n.changeLanguage("zh")}>
              {t("language.zh")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 w-16 h-16 rounded-full bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center">
            <Hourglass className="w-8 h-8 text-amber-600 dark:text-amber-400" />
          </div>
          <CardTitle>{t("auth.pendingTitle")}</CardTitle>
          <CardDescription>{t("auth.pendingDescription")}</CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          <p className="text-center text-muted-foreground">
            {t("auth.pendingMessage", { username: pendingUser?.username || "" })}
          </p>

          {/* What happens next section */}
          <div className="bg-muted/50 rounded-lg p-4 text-sm">
            <h4 className="font-medium mb-2">{t("auth.whatHappensNext")}</h4>
            <ul className="text-muted-foreground space-y-1">
              <li>- {t("auth.pendingStep1")}</li>
              <li>- {t("auth.pendingStep2")}</li>
            </ul>
          </div>

          {/* Status message */}
          {statusMessage && (
            <Alert variant={statusMessage.type === "error" ? "destructive" : "default"}>
              {statusMessage.type === "success" && <CheckCircle className="h-4 w-4" />}
              <AlertDescription>{statusMessage.text}</AlertDescription>
            </Alert>
          )}

          {/* Actions */}
          <div className="flex gap-3 justify-center">
            <Button variant="outline" onClick={checkStatus} disabled={checking}>
              {checking ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="mr-2 h-4 w-4" />
              )}
              {t("auth.checkStatus")}
            </Button>
            <Button variant="ghost" onClick={handleReturnToLogin}>
              <LogOut className="mr-2 h-4 w-4" />
              {t("auth.returnToLogin")}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
