import { useEffect, useState } from "react";
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
  PencilIcon
} from "@heroicons/react/24/outline";

export default function ProfileManager() {
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

  const fetchProfiles = async () => {
    try {
      const data = await api.getProfiles();
      setProfiles(data.profiles);
      setError(null);
    } catch (err: unknown) {
      setError((err as Error).message);
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
      setError((err as Error).message);
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteProfile = async (tag: string) => {
    if (!confirm(`确定要删除线路 ${tag} 吗？`)) return;

    setActionLoading(`delete-${tag}`);
    try {
      await api.deleteProfile(tag);
      fetchProfiles();
    } catch (err: unknown) {
      setError((err as Error).message);
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
      setError((err as Error).message);
    } finally {
      setActionLoading(null);
    }
  };

  const handleReconnect = async (tag: string) => {
    setActionLoading(`reconnect-${tag}`);
    try {
      await api.reconnectProfile(tag);
      fetchProfiles();
    } catch (err: unknown) {
      setError((err as Error).message);
    } finally {
      setActionLoading(null);
    }
  };

  const getRegionName = (regionId: string) => {
    const region = regions.find((r) => r.id === regionId);
    return region ? `${region.name} (${region.country})` : regionId;
  };

  // Group regions by country (put CN, HK and TW under 中国)
  const regionsByCountry = regions.reduce((acc, region) => {
    // Map CN, HK and TW to 中国 group
    const country = ["CN", "HK", "TW"].includes(region.country) ? "中国" : region.country;
    if (!acc[country]) acc[country] = [];
    acc[country].push(region);
    return acc;
  }, {} as Record<string, PiaRegion[]>);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">线路管理</h2>
          <p className="mt-1 text-sm text-slate-400">
            添加、编辑或删除 VPN 线路，选择连接到哪个地区
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={fetchProfiles}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl bg-white/5 px-4 py-2 text-sm text-slate-300 transition hover:bg-white/10 disabled:opacity-50"
          >
            <ArrowPathIcon className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            刷新
          </button>
          <button
            onClick={() => setShowNewForm(true)}
            className="flex items-center gap-2 rounded-xl bg-brand px-4 py-2 text-sm font-medium text-white transition hover:bg-brand/90"
          >
            <PlusIcon className="h-4 w-4" />
            添加线路
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-5 py-4">
          <p className="text-sm text-rose-300">{error}</p>
        </div>
      )}

      {/* New Profile Form */}
      {showNewForm && (
        <div className="rounded-2xl border border-brand/30 bg-brand/5 p-6">
          <h3 className="text-lg font-semibold text-white mb-4">添加新线路</h3>
          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                线路标识 (英文，如 uk-stream)
              </label>
              <input
                value={newTag}
                onChange={(e) => setNewTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                placeholder="uk-stream"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                描述
              </label>
              <input
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
                placeholder="英国流媒体线路"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                地区
              </label>
              <select
                value={newRegionId}
                onChange={(e) => setNewRegionId(e.target.value)}
                className="w-full rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-white"
              >
                <option value="">选择地区...</option>
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
              {actionLoading === "create" ? "创建中..." : "创建"}
            </button>
            <button
              onClick={() => setShowNewForm(false)}
              className="rounded-lg bg-white/10 px-4 py-2 text-sm text-slate-300"
            >
              取消
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
          <p className="mt-4 text-slate-400">还没有配置任何线路</p>
          <button
            onClick={() => setShowNewForm(true)}
            className="mt-4 rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white"
          >
            添加第一条线路
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
                    title="编辑"
                  >
                    <PencilIcon className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => handleDeleteProfile(profile.tag)}
                    disabled={actionLoading === `delete-${profile.tag}`}
                    className="rounded-lg p-2 text-slate-400 hover:bg-rose-500/20 hover:text-rose-400"
                    title="删除"
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
                      {actionLoading === `update-${profile.tag}` ? "保存中..." : "保存"}
                    </button>
                    <button
                      onClick={() => setEditingTag(null)}
                      className="rounded-lg bg-white/10 px-3 py-2 text-xs text-slate-300"
                    >
                      取消
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
                        连接中...
                      </>
                    ) : (
                      <>
                        <ArrowPathIcon className="h-3.5 w-3.5" />
                        {profile.is_connected ? "重新连接" : "连接"}
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
          <h4 className="font-semibold text-blue-200 mb-2">可用地区</h4>
          <p className="text-xs text-blue-300/80 mb-3">
            共 {regions.length} 个支持 WireGuard 的地区可供选择
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
                +{Object.keys(regionsByCountry).length - 10} 更多
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
