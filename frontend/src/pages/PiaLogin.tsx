import { FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import {
  UserCircleIcon,
  LockClosedIcon,
  ShieldCheckIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ArrowPathIcon,
  SignalIcon
} from "@heroicons/react/24/outline";

export default function PiaLogin() {
  const { t } = useTranslation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      setStatus(t('pia.enterCredentials'));
      setIsSuccess(false);
      return;
    }

    setLoading(true);
    setStatus(null);
    setIsSuccess(false);

    try {
      const response = await api.piaLogin(username, password);
      setStatus(response.message);
      setIsSuccess(true);
    } catch (error: unknown) {
      // L13 修复: 类型安全的错误处理
      const message = error instanceof Error ? error.message : t('pia.loginFailed');
      setStatus(message);
      setIsSuccess(false);
    } finally {
      setLoading(false);
    }
  };

  const isFormValid = username && password;

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white">{t('pia.title')}</h2>
        <p className="mt-2 text-sm text-slate-400">
          {t('pia.subtitle')}
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6 rounded-3xl border border-white/5 bg-gradient-to-br from-slate-900/60 to-slate-900/40 p-8 shadow-xl shadow-black/30">
        <div className="space-y-4">
          <div>
            <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-slate-400">
              <UserCircleIcon className="h-4 w-4" />
              {t('pia.username')}
            </label>
            <div className="relative mt-2">
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 pl-10 text-sm text-white placeholder-slate-500 transition focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
                placeholder="p1234567"
                disabled={loading}
              />
              <UserCircleIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
            </div>
          </div>

          <div>
            <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-slate-400">
              <LockClosedIcon className="h-4 w-4" />
              {t('pia.password')}
            </label>
            <div className="relative mt-2">
              <input
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 pl-10 text-sm text-white placeholder-slate-500 transition focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
                type="password"
                placeholder="••••••••••••"
                disabled={loading}
              />
              <LockClosedIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
            </div>
          </div>
        </div>

        {status && (
          <div className={`flex items-start gap-3 rounded-xl px-4 py-3 ${
            isSuccess
              ? 'bg-emerald-500/10 border border-emerald-500/20'
              : 'bg-rose-500/10 border border-rose-500/20'
          }`}>
            {isSuccess ? (
              <CheckCircleIcon className="mt-0.5 h-5 w-5 flex-shrink-0 text-emerald-400" />
            ) : (
              <ExclamationCircleIcon className="mt-0.5 h-5 w-5 flex-shrink-0 text-rose-400" />
            )}
            <div className="flex-1">
              <p className={`text-sm font-medium ${isSuccess ? 'text-emerald-300' : 'text-rose-300'}`}>
                {status}
              </p>
            </div>
          </div>
        )}

        <button
          type="submit"
          className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-brand to-blue-600 px-4 py-3.5 text-sm font-semibold text-white shadow-lg shadow-brand/20 transition hover:shadow-xl hover:shadow-brand/30 disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
          disabled={loading || !isFormValid}
        >
          {loading ? (
            <>
              <ArrowPathIcon className="h-5 w-5 animate-spin" />
              {t('pia.loggingIn')}
            </>
          ) : (
            <>
              <ShieldCheckIcon className="h-5 w-5" />
              {t('pia.login')}
            </>
          )}
        </button>
      </form>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-5">
          <div className="flex gap-3">
            <div className="rounded-lg bg-amber-500/20 p-2">
              <svg className="h-5 w-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div className="flex-1">
              <p className="font-semibold text-amber-200">{t('pia.securityNote')}</p>
              <p className="mt-1.5 text-xs leading-relaxed text-amber-300/90">
                {t('pia.securityNoteDesc')}
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-5">
          <div className="flex gap-3">
            <div className="rounded-lg bg-blue-500/20 p-2">
              <SignalIcon className="h-5 w-5 text-blue-400" />
            </div>
            <div className="flex-1">
              <p className="font-semibold text-blue-200">{t('pia.egressManagement')}</p>
              <p className="mt-1.5 text-xs leading-relaxed text-blue-300/90">
                {t('pia.egressManagementDesc')}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
