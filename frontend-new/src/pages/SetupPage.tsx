import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Languages, Lock, ShieldCheck, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/providers/AuthProvider";

export function SetupPage() {
  const { t, i18n } = useTranslation();
  const { setup, isSetup, isLoading: authLoading } = useAuth();
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (!authLoading && isSetup) {
      navigate("/", { replace: true });
    }
  }, [authLoading, isSetup, navigate]);

  const validatePasswordComplexity = (pwd: string): string | null => {
    if (pwd.length < 8) {
      return t("auth.passwordTooShort");
    }
    if (!/[A-Z]/.test(pwd)) {
      return t("auth.passwordNeedsUppercase");
    }
    if (!/[a-z]/.test(pwd)) {
      return t("auth.passwordNeedsLowercase");
    }
    if (!/\d/.test(pwd)) {
      return t("auth.passwordNeedsNumber");
    }
    return null;
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");

    const complexityError = validatePasswordComplexity(password);
    if (complexityError) {
      setError(complexityError);
      return;
    }

    if (password !== confirmPassword) {
      setError(t("auth.passwordMismatch"));
      return;
    }

    setIsSaving(true);

    try {
      await setup(password);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("auth.setupFailed"));
    } finally {
      setIsSaving(false);
    }
  };

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <CardTitle className="text-2xl">{t("auth.setupTitle")}</CardTitle>
          <CardDescription>{t("auth.setupSubtitle")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-6 rounded-lg border border-muted bg-muted/40 p-3 text-sm text-muted-foreground">
            <div className="flex items-start gap-2">
              <Lock className="mt-0.5 h-4 w-4 text-primary" />
              <span>{t("auth.setupHint")}</span>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="password">{t("auth.password")}</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t("auth.passwordPlaceholder")}
                disabled={isSaving}
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                {t("auth.passwordRequirementComplex")}
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm-password">{t("auth.confirmPassword")}</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder={t("auth.confirmPasswordPlaceholder")}
                disabled={isSaving}
              />
            </div>

            {error && (
              <div className="text-sm text-destructive">{error}</div>
            )}

            <Button
              type="submit"
              className="w-full"
              disabled={isSaving || !password || !confirmPassword}
            >
              {isSaving ? t("common.saving") : t("auth.createPassword")}
            </Button>
          </form>

          <div className="mt-6 flex justify-center">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm">
                  <Languages className="mr-2 h-4 w-4" />
                  {t("language.title")}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="center">
                <DropdownMenuItem onClick={() => i18n.changeLanguage("en")}>
                  {t("language.en")}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => i18n.changeLanguage("zh")}>
                  {t("language.zh")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
