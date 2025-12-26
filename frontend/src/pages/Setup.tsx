import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../contexts/AuthContext";
import { ShieldCheckIcon, LockClosedIcon } from "@heroicons/react/24/outline";
import LanguageSwitcher from "../components/LanguageSwitcher";

export default function Setup() {
  const { t } = useTranslation();
  const { setup, isSetup, isLoading: authLoading } = useAuth();
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // 如果已经设置过管理密码，直接跳转到主页
  useEffect(() => {
    if (!authLoading && isSetup) {
      navigate("/", { replace: true });
    }
  }, [authLoading, isSetup, navigate]);

  // 检测中显示 loading
  if (authLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-brand"></div>
      </div>
    );
  }

  // H9: 可配置的密码复杂度验证
  function validatePasswordComplexity(pwd: string): string | null {
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
  }

  async function handleSubmit(e: React.FormEvent) {
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

    setLoading(true);

    try {
      await setup(password);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("auth.setupFailed"));
    } finally {
      setPassword("");
      setConfirmPassword("");
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="rounded-3xl bg-gradient-to-br from-slate-900/90 to-slate-900/70 backdrop-blur-xl border border-white/10 p-8 shadow-2xl">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="inline-flex rounded-2xl bg-gradient-to-br from-brand to-blue-600 p-3 mb-4">
              <ShieldCheckIcon className="h-10 w-10 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white mb-2">
              {t("auth.setupTitle")}
            </h1>
            <p className="text-slate-400">{t("auth.setupSubtitle")}</p>
          </div>

          {/* Welcome message */}
          <div className="mb-6 p-4 rounded-xl bg-brand/10 border border-brand/20">
            <div className="flex gap-3">
              <LockClosedIcon className="h-5 w-5 text-brand flex-shrink-0 mt-0.5" />
              <div className="text-sm text-slate-300">{t("auth.setupHint")}</div>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                {t("auth.password")}
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent"
                placeholder={t("auth.passwordPlaceholder")}
                required
                minLength={8}
                autoFocus
              />
              <p className="mt-1 text-xs text-slate-500">
                {t("auth.passwordRequirementComplex")}
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                {t("auth.confirmPassword")}
              </label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent"
                placeholder={t("auth.confirmPasswordPlaceholder")}
                required
              />
            </div>

            {error && (
              <div className="p-3 rounded-lg bg-red-500/20 border border-red-500/30 text-red-400 text-sm">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !password || !confirmPassword}
              className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-brand to-blue-600 text-white font-semibold hover:from-brand/90 hover:to-blue-600/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {loading ? t("common.saving") : t("auth.createPassword")}
            </button>
          </form>

          {/* Language switcher */}
          <div className="mt-6 pt-6 border-t border-white/5 flex justify-center">
            <LanguageSwitcher />
          </div>
        </div>
      </div>
    </div>
  );
}
