import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../contexts/AuthContext";
import { ShieldCheckIcon } from "@heroicons/react/24/outline";
import LanguageSwitcher from "../components/LanguageSwitcher";

export default function Login() {
  const { t } = useTranslation();
  const { login } = useAuth();
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await login(password);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("auth.loginFailed"));
    } finally {
      setPassword("");
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
              {t("auth.loginTitle")}
            </h1>
            <p className="text-slate-400">{t("auth.loginSubtitle")}</p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
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
                autoFocus
              />
            </div>

            {error && (
              <div className="p-3 rounded-lg bg-red-500/20 border border-red-500/30 text-red-400 text-sm">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !password}
              className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-brand to-blue-600 text-white font-semibold hover:from-brand/90 hover:to-blue-600/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {loading ? t("common.loading") : t("auth.login")}
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
