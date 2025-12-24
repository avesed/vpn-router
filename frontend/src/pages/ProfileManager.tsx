import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { PiaRegion, VpnProfile } from "../types";
import {
  PlusIcon,
  TrashIcon,
  ArrowPathIcon,
  GlobeAltIcon,
  CheckCircleIcon,
  XCircleIcon,
  MapPinIcon,
  PencilIcon,
  KeyIcon
} from "@heroicons/react/24/outline";

export default function ProfileManager() {
  const { t } = useTranslation();
  const [profiles, setProfiles] = useState<VpnProfile[]>([]);
  const [regions, setRegions] = useState<PiaRegion[]>([]);
  const [loading, setLoading] = useState(true);
  const [regionsLoading, setRegionsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // New profile form
  const [showNewForm, setShowNewForm] = useState(false);
  const [newTag, setNewTag] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newRegionId, setNewRegionId] = useState("");

  // Edit mode
  const [editingTag, setEditingTag] = useState<string | null>(null);
  const [editRegionId, setEditRegionId] = useState("");

  // Login modal
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [pendingReconnectTag, setPendingReconnectTag] = useState<string | null>(null);

  const fetchProfiles = async () => {
    setError(null);
    try {
      const data = await api.getProfiles();
      setProfiles(data.profiles);
    } catch (err: unknown) {
      // L13 修复: 类型安全的错误处理
      setError(err instanceof Error ? err.message : "Failed to fetch profiles");
    } finally {
      setLoading(false);
    }
  };

  const fetchRegions = async () => {
    try {
      const data = await api.getPiaRegions();
      setRegions(data.regions);
    } catch (err: unknown) {
      console.error("Failed to fetch regions:", err);
    } finally {
      setRegionsLoading(false);
    }
  };

  useEffect(() => {
    fetchProfiles();
    fetchRegions();
  }, []);

  const handleCreateProfile = async () => {
    if (!newTag || !newDescription || !newRegionId) return;

    setActionLoading("create");
    try {
      await api.createProfile(newTag, newDescription, newRegionId);
      setShowNewForm(false);
      setNewTag("");
      setNewDescription("");
      setNewRegionId("");
      fetchProfiles();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Operation failed");
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteProfile = async (tag: string) => {
    if (!confirm(t("egress.confirmDeletePia", { name: tag }))) return;

    setActionLoading(`delete-${tag}`);
    try {
      await api.deleteProfile(tag);
      fetchProfiles();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Operation failed");
    } finally {
      setActionLoading(null);
    }
  };

  const handleUpdateProfile = async (tag: string) => {
    if (!editRegionId) return;

    setActionLoading(`update-${tag}`);
    try {
      await api.updateProfile(tag, { region_id: editRegionId });
      setEditingTag(null);
      setEditRegionId("");
      fetchProfiles();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Operation failed");
    } finally {
      setActionLoading(null);
    }
  };

  const handleReconnect = async (tag: string) => {
    setActionLoading(`reconnect-${tag}`);
    setError(null);
    try {
      // First check if credentials are available
      const credStatus = await api.getPiaCredentialsStatus();
      if (!credStatus.has_credentials) {
        // Show login modal instead of error
        setPendingReconnectTag(tag);
        setShowLoginModal(true);
        setActionLoading(null);
        return;
      }
      await api.reconnectProfile(tag);
      fetchProfiles();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Operation failed");
    } finally {
      setActionLoading(null);
    }
  };

  const handleLogin = async () => {
    if (!loginUsername || !loginPassword) return;
    setLoginLoading(true);
    setError(null);
    try {
      await api.piaLogin(loginUsername, loginPassword);
      setShowLoginModal(false);
      setLoginUsername("");
      setLoginPassword("");
      // If there was a pending reconnect, do it now
      if (pendingReconnectTag) {
        const tag = pendingReconnectTag;
        setPendingReconnectTag(null);
        await handleReconnect(tag);
      }
      fetchProfiles();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Operation failed");
    } finally {
      setLoginLoading(false);
    }
  };

  const getRegionName = (regionId: string) => {
    const region = regions.find((r) => r.id === regionId);
    return region ? `${region.name} (${region.country})` : regionId;
  };

  // Group regions by country (put CN, HK and TW under China group)
  const regionsByCountry = regions.reduce((acc, region) => {
    // Map CN, HK and TW to China group
    const country = ["CN", "HK", "TW"].includes(region.country) ? t("profile.chinaGroup") : region.country;
    if (!acc[country]) acc[country] = [];
    acc[country].push(region);
    return acc;
  }, {} as Record<string, PiaRegion[]>);

  return (
    <div className="space-y-4 md:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-xl md:text-2xl font-bold text-white">{t("profile.title")}</h2>
          <p className="mt-1 text-xs md:text-sm text-slate-400">
            {t("profile.subtitle")}
          </p>
        </div>
        <div className="flex gap-2 md:gap-3">
          <button
            onClick={fetchProfiles}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl bg-white/5 px-3 md:px-4 py-2 text-sm text-slate-300 transition hover:bg-white/10 disabled:opacity-50"
          >
            <ArrowPathIcon className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            <span className="hidden sm:inline">{t("common.refresh")}</span>
          </button>
          <button
            onClick={() => setShowNewForm(true)}
            className="flex items-center gap-2 rounded-xl bg-brand px-3 md:px-4 py-2 text-sm font-medium text-white transition hover:bg-brand/90"
          >
            <PlusIcon className="h-4 w-4" />
            <span className="hidden sm:inline">{t("egress.addPiaLine")}</span>
            <span className="sm:hidden">{t("common.add")}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-5 py-4">
          <p className="text-sm text-rose-300">{error}</p>
        </div>
      )}

      {/* Login Modal */}
      {showLoginModal && createPortal(
        <div className="fixed inset-0 bg-black/60 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-6 shadow-2xl">
              <div className="flex items-center gap-3 mb-6">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand/20">
                  <KeyIcon className="h-5 w-5 text-brand" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white">{t("pia.loginTitle")}</h3>
                  <p className="text-sm text-slate-400">{t("pia.loginRequired")}</p>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">{t("pia.username")}</label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    className="w-full rounded-lg border border-white/10 bg-slate-800/60 px-3 py-2 text-sm text-white focus:border-brand focus:outline-none"
                    placeholder={t("pia.usernamePlaceholder")}
                    autoFocus
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">{t("pia.password")}</label>
                  <input
                    type="password"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    className="w-full rounded-lg border border-white/10 bg-slate-800/60 px-3 py-2 text-sm text-white focus:border-brand focus:outline-none"
                    placeholder={t("pia.passwordPlaceholder")}
                    onKeyDown={(e) => e.key === "Enter" && handleLogin()}
                  />
                </div>
              </div>
              <div className="mt-6 flex gap-3">
                <button
                  onClick={handleLogin}
                  disabled={!loginUsername || !loginPassword || loginLoading}
                  className="flex-1 rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
                >
                  {loginLoading ? t("pia.loggingIn") : t("pia.loginAndConnect")}
                </button>
                <button
                  onClick={() => {
                    setShowLoginModal(false);
                    setPendingReconnectTag(null);
                    setLoginUsername("");
                    setLoginPassword("");
                  }}
                  className="rounded-lg bg-white/10 px-4 py-2 text-sm text-slate-300 hover:bg-white/20"
                >
                  {t("common.cancel")}
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* New Profile Form */}
      {showNewForm && (
        <div className="rounded-2xl border border-brand/30 bg-brand/5 p-6">
          <h3 className="text-lg font-semibold text-white mb-4">{t("egress.addPiaLine")}</h3>
          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t("egress.lineTag")} ({t("egress.lineTagHint")})
              </label>
              <input
                value={newTag}
                onChange={(e) => setNewTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                placeholder={t("egress.lineTagPlaceholder")}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t("common.description")}
              </label>
              <input
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                placeholder={t("egress.descriptionPlaceholder")}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                {t("egress.region")}
              </label>
              <select
                value={newRegionId}
                onChange={(e) => setNewRegionId(e.target.value)}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
              >
                <option value="">{t("egress.selectRegion")}</option>
                {Object.entries(regionsByCountry).map(([country, countryRegions]) => (
                  <optgroup key={country} label={country}>
                    {countryRegions.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.name}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </div>
          </div>
          <div className="mt-4 flex gap-3">
            <button
              onClick={handleCreateProfile}
              disabled={!newTag || !newDescription || !newRegionId || actionLoading === "create"}
              className="rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {actionLoading === "create" ? t("common.creating") : t("common.create")}
            </button>
            <button
              onClick={() => setShowNewForm(false)}
              className="rounded-lg bg-white/10 px-4 py-2 text-sm text-slate-300"
            >
              {t("common.cancel")}
            </button>
          </div>
        </div>
      )}

      {/* Profiles List */}
      {loading ? (
        <div className="flex justify-center py-12">
          <div className="h-10 w-10 animate-spin rounded-full border-4 border-slate-700 border-t-blue-500" />
        </div>
      ) : profiles.length === 0 ? (
        <div className="rounded-2xl border border-white/5 bg-slate-900/40 p-12 text-center">
          <GlobeAltIcon className="mx-auto h-12 w-12 text-slate-600" />
          <p className="mt-4 text-slate-400">{t("egress.noPiaLines")}</p>
          <button
            onClick={() => setShowNewForm(true)}
            className="mt-4 rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white"
          >
            {t("profile.addFirstLine")}
          </button>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {profiles.map((profile) => (
            <div
              key={profile.tag}
              className={`rounded-2xl border p-5 transition-all overflow-hidden ${
                profile.is_connected
                  ? "border-emerald-500/30 bg-gradient-to-br from-emerald-500/10 to-emerald-500/5"
                  : "border-white/5 bg-slate-900/40"
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-semibold text-white">{profile.tag}</h4>
                    {profile.is_connected ? (
                      <CheckCircleIcon className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <XCircleIcon className="h-4 w-4 text-slate-500" />
                    )}
                  </div>
                  <p className="mt-1 text-sm text-slate-400">{profile.description}</p>
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={() => {
                      setEditingTag(profile.tag);
                      setEditRegionId(profile.region_id);
                    }}
                    className="rounded-lg p-2 text-slate-400 hover:bg-white/10 hover:text-white"
                    title={t("common.edit")}
                  >
                    <PencilIcon className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => handleDeleteProfile(profile.tag)}
                    disabled={actionLoading === `delete-${profile.tag}`}
                    className="rounded-lg p-2 text-slate-400 hover:bg-rose-500/20 hover:text-rose-400"
                    title={t("common.delete")}
                  >
                    <TrashIcon className="h-4 w-4" />
                  </button>
                </div>
              </div>

              <div className="mt-4 space-y-2">
                <div className="flex items-center gap-2 text-sm min-w-0">
                  <MapPinIcon className="h-4 w-4 text-slate-500 flex-shrink-0" />
                  {editingTag === profile.tag ? (
                    <select
                      value={editRegionId}
                      onChange={(e) => setEditRegionId(e.target.value)}
                      className="flex-1 min-w-0 rounded border border-white/10 bg-slate-800 px-2 py-1 text-xs text-white"
                    >
                      {Object.entries(regionsByCountry).map(([country, countryRegions]) => (
                        <optgroup key={country} label={country}>
                          {countryRegions.map((r) => (
                            <option key={r.id} value={r.id}>
                              {r.name}
                            </option>
                          ))}
                        </optgroup>
                      ))}
                    </select>
                  ) : (
                    <span className="text-slate-300">{getRegionName(profile.region_id)}</span>
                  )}
                </div>

                {profile.server_ip && (
                  <div className="rounded-lg bg-black/20 px-3 py-2">
                    <p className="font-mono text-xs text-slate-400">
                      {profile.server_ip}:{profile.server_port}
                    </p>
                  </div>
                )}
              </div>

              <div className="mt-4 flex gap-2">
                {editingTag === profile.tag ? (
                  <>
                    <button
                      onClick={() => handleUpdateProfile(profile.tag)}
                      disabled={actionLoading === `update-${profile.tag}`}
                      className="flex-1 rounded-lg bg-brand px-3 py-2 text-xs font-medium text-white"
                    >
                      {actionLoading === `update-${profile.tag}` ? t("common.saving") : t("common.save")}
                    </button>
                    <button
                      onClick={() => setEditingTag(null)}
                      className="rounded-lg bg-white/10 px-3 py-2 text-xs text-slate-300"
                    >
                      {t("common.cancel")}
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => handleReconnect(profile.tag)}
                    disabled={actionLoading === `reconnect-${profile.tag}`}
                    className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-slate-800/50 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700"
                  >
                    {actionLoading === `reconnect-${profile.tag}` ? (
                      <>
                        <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                        {t("common.connecting")}
                      </>
                    ) : (
                      <>
                        <ArrowPathIcon className="h-3.5 w-3.5" />
                        {profile.is_connected ? t("egress.reconnect") : t("egress.connect")}
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Available Regions Info */}
      {!regionsLoading && regions.length > 0 && (
        <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-5">
          <h4 className="font-semibold text-blue-200 mb-2">{t("profile.availableRegions")}</h4>
          <p className="text-xs text-blue-300/80 mb-3">
            {t("egress.piaRegionsAvailable", { count: regions.length })}
          </p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(regionsByCountry).slice(0, 10).map(([country, countryRegions]) => (
              <span
                key={country}
                className="rounded-full bg-blue-500/20 px-2.5 py-1 text-xs text-blue-300"
              >
                {country} ({countryRegions.length})
              </span>
            ))}
            {Object.keys(regionsByCountry).length > 10 && (
              <span className="rounded-full bg-slate-500/20 px-2.5 py-1 text-xs text-slate-400">
                +{Object.keys(regionsByCountry).length - 10} {t("common.more")}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
