import { useState, useEffect, useCallback, useRef } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { EgressItem, CustomEgress, WireGuardConfParseResult, PiaRegion, VpnProfile } from "../types";
import {
  PlusIcon,
  TrashIcon,
  ArrowPathIcon,
  GlobeAltIcon,
  ServerIcon,
  ArrowUpTrayIcon,
  ClipboardDocumentIcon,
  XMarkIcon,
  CheckIcon,
  PencilIcon,
  ShieldCheckIcon,
  MapPinIcon,
  CheckCircleIcon,
  XCircleIcon,
  ChevronUpDownIcon,
  MagnifyingGlassIcon,
  KeyIcon
} from "@heroicons/react/24/outline";

type TabType = "all" | "pia" | "custom";
type ImportMethod = "upload" | "paste" | "manual";

export default function EgressManager() {
  const { t } = useTranslation();
  const [piaEgress, setPiaEgress] = useState<EgressItem[]>([]);
  const [customEgress, setCustomEgress] = useState<CustomEgress[]>([]);
  const [piaProfiles, setPiaProfiles] = useState<VpnProfile[]>([]);
  const [piaRegions, setPiaRegions] = useState<PiaRegion[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("all");

  // Add custom modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [importMethod, setImportMethod] = useState<ImportMethod>("upload");
  const [pasteContent, setPasteContent] = useState("");
  const [parsedConfig, setParsedConfig] = useState<WireGuardConfParseResult | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Custom egress form fields
  const [formTag, setFormTag] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formServer, setFormServer] = useState("");
  const [formPort, setFormPort] = useState(51820);
  const [formPrivateKey, setFormPrivateKey] = useState("");
  const [formPublicKey, setFormPublicKey] = useState("");
  const [formAddress, setFormAddress] = useState("");
  const [formMtu, setFormMtu] = useState(1420);
  const [formDns, setFormDns] = useState("1.1.1.1");
  const [formPreSharedKey, setFormPreSharedKey] = useState("");

  // Edit custom modal
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingEgress, setEditingEgress] = useState<CustomEgress | null>(null);

  // PIA modal
  const [showPiaModal, setShowPiaModal] = useState(false);
  const [piaModalMode, setPiaModalMode] = useState<"add" | "edit">("add");
  const [editingPiaProfile, setEditingPiaProfile] = useState<VpnProfile | null>(null);
  const [piaFormTag, setPiaFormTag] = useState("");
  const [piaFormDescription, setPiaFormDescription] = useState("");
  const [piaFormRegionId, setPiaFormRegionId] = useState("");

  // Region dropdown state
  const [regionDropdownOpen, setRegionDropdownOpen] = useState(false);
  const [regionSearchQuery, setRegionSearchQuery] = useState("");
  const regionDropdownRef = useRef<HTMLDivElement>(null);

  // Login modal state
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [pendingReconnectTag, setPendingReconnectTag] = useState<string | null>(null);

  const loadEgress = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [allData, customData, profilesData] = await Promise.all([
        api.getAllEgress(),
        api.getCustomEgress(),
        api.getProfiles()
      ]);
      setPiaEgress(allData.pia);
      setCustomEgress(customData.egress);
      setPiaProfiles(profilesData.profiles);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('egress.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  const loadPiaRegions = useCallback(async () => {
    try {
      const data = await api.getPiaRegions();
      setPiaRegions(data.regions);
    } catch (err) {
      console.error("Failed to load PIA regions:", err);
    }
  }, []);

  useEffect(() => {
    loadEgress();
    loadPiaRegions();
  }, [loadEgress, loadPiaRegions]);

  // Group regions by country
  const regionsByCountry = piaRegions.reduce((acc, region) => {
    const country = ["CN", "HK", "TW"].includes(region.country) ? "中国" : region.country;
    if (!acc[country]) acc[country] = [];
    acc[country].push(region);
    return acc;
  }, {} as Record<string, PiaRegion[]>);

  const getRegionName = (regionId: string) => {
    const region = piaRegions.find((r) => r.id === regionId);
    return region ? `${region.name} (${region.country})` : regionId;
  };

  const resetForm = () => {
    setFormTag("");
    setFormDescription("");
    setFormServer("");
    setFormPort(51820);
    setFormPrivateKey("");
    setFormPublicKey("");
    setFormAddress("");
    setFormMtu(1420);
    setFormDns("1.1.1.1");
    setFormPreSharedKey("");
    setParsedConfig(null);
    setPasteContent("");
    setParseError(null);
  };

  const resetPiaForm = () => {
    setPiaFormTag("");
    setPiaFormDescription("");
    setPiaFormRegionId("");
    setEditingPiaProfile(null);
    setRegionDropdownOpen(false);
    setRegionSearchQuery("");
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (regionDropdownRef.current && !regionDropdownRef.current.contains(event.target as Node)) {
        setRegionDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Filter regions based on search
  const filteredRegionsByCountry = Object.entries(regionsByCountry).reduce((acc, [country, regions]) => {
    const filtered = regions.filter(
      (r) =>
        r.name.toLowerCase().includes(regionSearchQuery.toLowerCase()) ||
        r.id.toLowerCase().includes(regionSearchQuery.toLowerCase()) ||
        country.toLowerCase().includes(regionSearchQuery.toLowerCase())
    );
    if (filtered.length > 0) acc[country] = filtered;
    return acc;
  }, {} as Record<string, PiaRegion[]>);

  // ============ PIA Profile Management ============

  const handleAddPiaProfile = () => {
    resetPiaForm();
    setPiaModalMode("add");
    setShowPiaModal(true);
  };

  const handleEditPiaProfile = (profile: VpnProfile) => {
    setEditingPiaProfile(profile);
    setPiaFormTag(profile.tag);
    setPiaFormDescription(profile.description);
    setPiaFormRegionId(profile.region_id);
    setPiaModalMode("edit");
    setShowPiaModal(true);
  };

  const handleCreatePiaProfile = async () => {
    if (!piaFormTag || !piaFormDescription || !piaFormRegionId) return;

    setActionLoading("create-pia");
    try {
      await api.createProfile(piaFormTag, piaFormDescription, piaFormRegionId);
      setSuccessMessage(t('egress.piaLineAddSuccess'));
      setShowPiaModal(false);
      resetPiaForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.createFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleUpdatePiaProfile = async () => {
    if (!editingPiaProfile || !piaFormRegionId) return;

    setActionLoading("update-pia");
    try {
      await api.updateProfile(editingPiaProfile.tag, {
        description: piaFormDescription,
        region_id: piaFormRegionId
      });
      setSuccessMessage(t('egress.piaLineUpdated'));
      setShowPiaModal(false);
      resetPiaForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.updateFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeletePiaProfile = async (tag: string) => {
    if (!confirm(t('egress.confirmDeletePiaLine', { tag }))) return;

    setActionLoading(`delete-pia-${tag}`);
    try {
      await api.deleteProfile(tag);
      setSuccessMessage(t('egress.piaLineDeleted', { tag }));
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.deleteFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleReconnectPiaProfile = async (tag: string) => {
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
      setSuccessMessage(t('egress.piaLineReconnecting', { tag }));
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('egress.reconnectFailed'));
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
        await handleReconnectPiaProfile(tag);
      }
      loadEgress();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('pia.loginFailed'));
    } finally {
      setLoginLoading(false);
    }
  };

  // ============ Custom Egress Management ============

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const content = await file.text();
      await parseConfig(content);
      const baseName = file.name.replace(/\.conf$/i, "").toLowerCase().replace(/[^a-z0-9-]/g, "-");
      setFormTag(baseName);
    } catch (err) {
      setParseError(err instanceof Error ? err.message : t('customEgress.fileParseError'));
    }
  };

  const parseConfig = async (content: string) => {
    try {
      setParseError(null);
      const result = await api.parseWireGuardConf(content);
      setParsedConfig(result);
      setFormServer(result.server);
      setFormPort(result.port);
      setFormPrivateKey(result.private_key);
      setFormPublicKey(result.public_key);
      setFormAddress(result.address);
      if (result.mtu) setFormMtu(result.mtu);
      if (result.dns) setFormDns(result.dns);
      if (result.pre_shared_key) setFormPreSharedKey(result.pre_shared_key);
    } catch (err) {
      setParseError(err instanceof Error ? err.message : t('customEgress.parseError'));
      throw err;
    }
  };

  const handlePasteConfig = async () => {
    if (!pasteContent.trim()) {
      setParseError(t('customEgress.pasteContentError'));
      return;
    }
    try {
      await parseConfig(pasteContent);
    } catch {
      // Error already handled
    }
  };

  const handleCreateEgress = async () => {
    if (!formTag.trim() || !formServer.trim() || !formPrivateKey.trim() || !formPublicKey.trim() || !formAddress.trim()) {
      setError(t('customEgress.fillAllFieldsError'));
      return;
    }

    setActionLoading("create");
    try {
      await api.createCustomEgress({
        tag: formTag.trim(),
        description: formDescription.trim(),
        server: formServer.trim(),
        port: formPort,
        private_key: formPrivateKey.trim(),
        public_key: formPublicKey.trim(),
        address: formAddress.trim(),
        mtu: formMtu,
        dns: formDns.trim(),
        pre_shared_key: formPreSharedKey.trim() || undefined
      });
      setSuccessMessage(t('customEgress.addSuccess'));
      setShowAddModal(false);
      resetForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.createFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleEditEgress = (egress: CustomEgress) => {
    setEditingEgress(egress);
    setFormTag(egress.tag);
    setFormDescription(egress.description);
    setFormServer(egress.server);
    setFormPort(egress.port);
    setFormPrivateKey(egress.private_key);
    setFormPublicKey(egress.public_key);
    setFormAddress(egress.address);
    setFormMtu(egress.mtu);
    setFormDns(egress.dns);
    setFormPreSharedKey(egress.pre_shared_key || "");
    setShowEditModal(true);
  };

  const handleUpdateEgress = async () => {
    if (!editingEgress) return;

    setActionLoading("update");
    try {
      await api.updateCustomEgress(editingEgress.tag, {
        description: formDescription.trim(),
        server: formServer.trim(),
        port: formPort,
        private_key: formPrivateKey.trim(),
        public_key: formPublicKey.trim(),
        address: formAddress.trim(),
        mtu: formMtu,
        dns: formDns.trim(),
        pre_shared_key: formPreSharedKey.trim() || undefined
      });
      setSuccessMessage(t('customEgress.updateSuccess'));
      setShowEditModal(false);
      setEditingEgress(null);
      resetForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.updateFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteEgress = async (tag: string) => {
    if (!confirm(t('customEgress.confirmDelete', { tag }))) return;

    setActionLoading(`delete-${tag}`);
    try {
      await api.deleteCustomEgress(tag);
      setSuccessMessage(t('customEgress.deleteSuccess', { tag }));
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.deleteFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const filteredPia = activeTab === "custom" ? [] : piaProfiles;
  const filteredCustom = activeTab === "pia" ? [] : customEgress;
  const totalCount = piaProfiles.length + customEgress.length;

  if (loading && !piaProfiles.length && !customEgress.length) {
    return (
      <div className="flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-brand border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-[calc(100vh-12rem)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">{t('egress.title')}</h1>
          <p className="text-slate-400 mt-1">{t('egress.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadEgress}
            disabled={loading}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors disabled:opacity-50"
            title={t('common.refresh')}
          >
            <ArrowPathIcon className={`h-5 w-5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-4 text-red-400 mb-4">
          {error}
          <button onClick={() => setError(null)} className="float-right">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
      )}
      {successMessage && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/20 p-4 text-emerald-400 flex items-center gap-2 mb-4">
          <CheckIcon className="h-5 w-5" />
          {successMessage}
        </div>
      )}

      {/* Login Modal */}
      {showLoginModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-6">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand/20">
                <KeyIcon className="h-5 w-5 text-brand" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white">{t('pia.loginTitle')}</h3>
                <p className="text-sm text-slate-400">{t('pia.loginRequired')}</p>
              </div>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">{t('pia.username')}</label>
                <input
                  type="text"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  className="w-full rounded-lg border border-white/10 bg-slate-800/60 px-3 py-2 text-sm text-white focus:border-brand focus:outline-none"
                  placeholder={t('pia.usernamePlaceholder')}
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">{t('pia.password')}</label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full rounded-lg border border-white/10 bg-slate-800/60 px-3 py-2 text-sm text-white focus:border-brand focus:outline-none"
                  placeholder={t('pia.passwordPlaceholder')}
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
                {loginLoading ? t('pia.loggingIn') : t('pia.loginAndConnect')}
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
                {t('common.cancel')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-white/10 pb-2 mb-6">
        {[
          { key: "all", label: `${t('common.all')} (${totalCount})` },
          { key: "pia", label: `${t('egress.pia')} (${piaProfiles.length})` },
          { key: "custom", label: `${t('egress.custom')} (${customEgress.length})` }
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as TabType)}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
              activeTab === tab.key
                ? "bg-brand text-white"
                : "text-slate-400 hover:text-white hover:bg-white/5"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Egress List */}
      {filteredPia.length === 0 && filteredCustom.length === 0 ? (
        <div className="flex-1 rounded-xl bg-white/5 border border-white/10 p-12 text-center flex flex-col items-center justify-center">
          <GlobeAltIcon className="h-12 w-12 text-slate-600 mb-4" />
          <p className="text-slate-400">
            {activeTab === "custom" ? t('egress.noCustomEgress') : activeTab === "pia" ? t('egress.noPiaLines') : t('egress.noEgressFound')}
          </p>
          {activeTab !== "all" && (
            <div className="mt-4">
              {activeTab === "pia" && (
                <button
                  onClick={handleAddPiaProfile}
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium"
                >
                  {t('egress.addPiaLine')}
                </button>
              )}
              {activeTab === "custom" && (
                <button
                  onClick={() => setShowAddModal(true)}
                  className="px-4 py-2 rounded-lg bg-brand text-white text-sm font-medium"
                >
                  {t('egress.addCustomEgress')}
                </button>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="flex-1 rounded-xl bg-white/5 border border-white/10 p-6 space-y-6 overflow-y-auto">
          {/* PIA Egress */}
          {filteredPia.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
                  <ShieldCheckIcon className="h-4 w-4" />
                  {t('egress.piaLines')} ({filteredPia.length})
                </h3>
                {activeTab === "pia" && (
                  <button
                    onClick={handleAddPiaProfile}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 text-xs font-medium transition-colors"
                  >
                    <PlusIcon className="h-3.5 w-3.5" />
                    {t('egress.addLine')}
                  </button>
                )}
              </div>
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                {filteredPia.map((profile) => (
                  <div
                    key={profile.tag}
                    className={`rounded-xl border p-4 transition-all ${
                      profile.is_connected
                        ? "bg-emerald-500/5 border-emerald-500/20"
                        : "bg-white/5 border-white/10"
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${profile.is_connected ? "bg-emerald-500/20" : "bg-white/10"}`}>
                          <ShieldCheckIcon className={`h-5 w-5 ${profile.is_connected ? "text-emerald-400" : "text-slate-400"}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-semibold text-white">{profile.tag}</h4>
                            {profile.is_connected ? (
                              <CheckCircleIcon className="h-4 w-4 text-emerald-400" />
                            ) : (
                              <XCircleIcon className="h-4 w-4 text-slate-500" />
                            )}
                          </div>
                          <p className="text-xs text-slate-500">{profile.description}</p>
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleEditPiaProfile(profile)}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-white/10 hover:text-white"
                          title={t('common.edit')}
                        >
                          <PencilIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeletePiaProfile(profile.tag)}
                          disabled={actionLoading === `delete-pia-${profile.tag}`}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                          title={t('common.delete')}
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>

                    <div className="mt-3 pt-3 border-t border-white/5 space-y-2">
                      <div className="flex items-center gap-2 text-xs">
                        <MapPinIcon className="h-3.5 w-3.5 text-slate-500" />
                        <span className="text-slate-400">{getRegionName(profile.region_id)}</span>
                      </div>
                      {profile.server_ip && (
                        <p className="text-xs font-mono text-slate-500">
                          {profile.server_ip}:{profile.server_port}
                        </p>
                      )}
                    </div>

                    <div className="mt-3">
                      <button
                        onClick={() => handleReconnectPiaProfile(profile.tag)}
                        disabled={actionLoading === `reconnect-${profile.tag}`}
                        className="w-full flex items-center justify-center gap-2 rounded-lg bg-slate-800/50 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 transition-colors"
                      >
                        {actionLoading === `reconnect-${profile.tag}` ? (
                          <>
                            <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                            {t('common.connecting')}
                          </>
                        ) : (
                          <>
                            <ArrowPathIcon className="h-3.5 w-3.5" />
                            {profile.is_connected ? t('egress.reconnect') : t('egress.connect')}
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Custom Egress */}
          {filteredCustom.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
                  <ServerIcon className="h-4 w-4" />
                  {t('egress.customEgress')} ({filteredCustom.length})
                </h3>
                {activeTab === "custom" && (
                  <button
                    onClick={() => {
                      resetForm();
                      setShowAddModal(true);
                    }}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 text-xs font-medium transition-colors"
                  >
                    <PlusIcon className="h-3.5 w-3.5" />
                    {t('egress.addEgress')}
                  </button>
                )}
              </div>
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                {filteredCustom.map((egress) => (
                  <div
                    key={egress.tag}
                    className="rounded-xl border bg-blue-500/5 border-blue-500/20 p-4"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-blue-500/20">
                          <ServerIcon className="h-5 w-5 text-blue-400" />
                        </div>
                        <div>
                          <h4 className="font-semibold text-white">{egress.tag}</h4>
                          <p className="text-xs text-slate-500">{egress.description || t('customEgress.defaultDescription')}</p>
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleEditEgress(egress)}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-white/10 hover:text-white"
                          title={t('common.edit')}
                        >
                          <PencilIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteEgress(egress.tag)}
                          disabled={actionLoading === `delete-${egress.tag}`}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                          title={t('common.delete')}
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                    <div className="mt-3 pt-3 border-t border-white/5 space-y-1">
                      <p className="text-xs font-mono text-slate-400">
                        {egress.server}:{egress.port}
                      </p>
                      <p className="text-xs text-slate-500">
                        {t('customEgress.addressLabel')}: {egress.address} | MTU: {egress.mtu}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}

      {/* PIA Modal */}
      {showPiaModal && (
        <div className="fixed inset-0 bg-black/50 flex items-start justify-center z-50 overflow-y-auto">
          <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg m-4">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">
                  {piaModalMode === "add" ? t('egress.addPiaLine') : t('egress.editPiaLine', { tag: editingPiaProfile?.tag })}
                </h2>
                <button
                  onClick={() => {
                    setShowPiaModal(false);
                    resetPiaForm();
                  }}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              {piaModalMode === "add" && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t('egress.lineTag')} <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    value={piaFormTag}
                    onChange={(e) => setPiaFormTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-"))}
                    placeholder={t('egress.lineTagPlaceholder')}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                  <p className="text-xs text-slate-500 mt-1">{t('egress.lineTagHint')}</p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t('common.description')} <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={piaFormDescription}
                  onChange={(e) => setPiaFormDescription(e.target.value)}
                  placeholder={t('egress.descriptionPlaceholder')}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t('egress.region')} <span className="text-red-400">*</span>
                </label>
                {/* Custom Region Dropdown */}
                <div className="relative" ref={regionDropdownRef}>
                  <button
                    type="button"
                    onClick={() => setRegionDropdownOpen(!regionDropdownOpen)}
                    className="w-full px-3 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-brand flex items-center justify-between transition-colors hover:bg-slate-700"
                  >
                    <span className={piaFormRegionId ? "text-white" : "text-slate-400"}>
                      {piaFormRegionId ? getRegionName(piaFormRegionId) : t('egress.selectRegion')}
                    </span>
                    <ChevronUpDownIcon className="h-5 w-5 text-slate-400" />
                  </button>

                  {regionDropdownOpen && (
                    <div className="absolute z-50 mt-1 w-full rounded-xl bg-slate-800 border border-white/10 shadow-xl shadow-black/50 overflow-hidden">
                      {/* Search Input */}
                      <div className="p-2 border-b border-white/10">
                        <div className="relative">
                          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                          <input
                            type="text"
                            value={regionSearchQuery}
                            onChange={(e) => setRegionSearchQuery(e.target.value)}
                            placeholder={t('egress.searchRegion')}
                            className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-900/50 border border-white/5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-brand/50"
                            autoFocus
                          />
                        </div>
                      </div>

                      {/* Region List */}
                      <div className="max-h-64 overflow-y-auto">
                        {Object.keys(filteredRegionsByCountry).length === 0 ? (
                          <div className="px-4 py-3 text-sm text-slate-500 text-center">
                            {t('common.noMatchingResults')}
                          </div>
                        ) : (
                          Object.entries(filteredRegionsByCountry).map(([country, countryRegions]) => (
                            <div key={country}>
                              <div className="px-3 py-1.5 text-xs font-semibold text-slate-400 bg-slate-900/50 sticky top-0">
                                {country}
                              </div>
                              {countryRegions.map((r) => (
                                <button
                                  key={r.id}
                                  type="button"
                                  onClick={() => {
                                    setPiaFormRegionId(r.id);
                                    setRegionDropdownOpen(false);
                                    setRegionSearchQuery("");
                                  }}
                                  className={`w-full px-3 py-2 text-left text-sm transition-colors flex items-center justify-between ${
                                    piaFormRegionId === r.id
                                      ? "bg-brand/20 text-brand"
                                      : "text-white hover:bg-white/5"
                                  }`}
                                >
                                  <span>{r.name}</span>
                                  {piaFormRegionId === r.id && (
                                    <CheckIcon className="h-4 w-4 text-brand" />
                                  )}
                                </button>
                              ))}
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {piaRegions.length > 0 && (
                <div className="rounded-lg bg-blue-500/10 border border-blue-500/20 p-3">
                  <p className="text-xs text-blue-300">
                    {t('egress.piaRegionsAvailable', { count: piaRegions.length })}
                  </p>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowPiaModal(false);
                  resetPiaForm();
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={piaModalMode === "add" ? handleCreatePiaProfile : handleUpdatePiaProfile}
                disabled={
                  (piaModalMode === "add" ? actionLoading === "create-pia" : actionLoading === "update-pia") ||
                  (piaModalMode === "add" && (!piaFormTag || !piaFormDescription || !piaFormRegionId)) ||
                  (piaModalMode === "edit" && !piaFormRegionId)
                }
                className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {(actionLoading === "create-pia" || actionLoading === "update-pia") ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : piaModalMode === "add" ? (
                  <PlusIcon className="h-4 w-4" />
                ) : (
                  <CheckIcon className="h-4 w-4" />
                )}
                {piaModalMode === "add" ? t('common.add') : t('common.save')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Custom Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-start justify-center z-50 overflow-y-auto">
          <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-2xl m-4">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">{t('egress.addCustomEgress')}</h2>
                <button
                  onClick={() => {
                    setShowAddModal(false);
                    resetForm();
                  }}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-6">
              {/* Import Method Tabs */}
              <div className="flex gap-2">
                {[
                  { key: "upload", label: t('customEgress.uploadFile'), icon: ArrowUpTrayIcon },
                  { key: "paste", label: t('customEgress.pasteConfig'), icon: ClipboardDocumentIcon },
                  { key: "manual", label: t('customEgress.manualInput'), icon: PencilIcon }
                ].map((method) => (
                  <button
                    key={method.key}
                    onClick={() => setImportMethod(method.key as ImportMethod)}
                    className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                      importMethod === method.key
                        ? "bg-brand text-white"
                        : "text-slate-400 hover:text-white bg-white/5 hover:bg-white/10"
                    }`}
                  >
                    <method.icon className="h-4 w-4" />
                    {method.label}
                  </button>
                ))}
              </div>

              {/* Upload */}
              {importMethod === "upload" && (
                <div className="space-y-4">
                  <input
                    type="file"
                    ref={fileInputRef}
                    accept=".conf"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="w-full border-2 border-dashed border-white/20 rounded-xl p-8 text-center hover:border-brand/50 hover:bg-brand/5 transition-colors"
                  >
                    <ArrowUpTrayIcon className="h-8 w-8 text-slate-400 mx-auto mb-2" />
                    <p className="text-slate-300">{t('customEgress.uploadPrompt')}</p>
                    <p className="text-xs text-slate-500 mt-1">{t('customEgress.uploadHint')}</p>
                  </button>
                  {parsedConfig && (
                    <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-3">
                      <p className="text-sm text-emerald-400">{t('customEgress.parseSuccess')}</p>
                      <p className="text-xs text-emerald-300 mt-1">{t('customEgress.serverInfo', { server: parsedConfig.server, port: parsedConfig.port })}</p>
                    </div>
                  )}
                </div>
              )}

              {/* Paste */}
              {importMethod === "paste" && (
                <div className="space-y-4">
                  <textarea
                    value={pasteContent}
                    onChange={(e) => setPasteContent(e.target.value)}
                    placeholder={t('customEgress.pastePlaceholder')}
                    className="w-full h-48 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono text-sm placeholder-slate-500 focus:outline-none focus:border-brand resize-none"
                  />
                  <button
                    onClick={handlePasteConfig}
                    className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium"
                  >
                    {t('customEgress.parseButton')}
                  </button>
                  {parsedConfig && (
                    <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-3">
                      <p className="text-sm text-emerald-400">{t('customEgress.parseSuccess')}</p>
                      <p className="text-xs text-emerald-300 mt-1">{t('customEgress.serverInfo', { server: parsedConfig.server, port: parsedConfig.port })}</p>
                    </div>
                  )}
                </div>
              )}

              {parseError && (
                <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3">
                  <p className="text-sm text-red-400">{parseError}</p>
                </div>
              )}

              {/* Form Fields */}
              {(importMethod === "manual" || parsedConfig) && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('customEgress.identifier')} <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="text"
                        value={formTag}
                        onChange={(e) => setFormTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-"))}
                        placeholder={t('customEgress.identifierPlaceholder')}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('common.description')}</label>
                      <input
                        type="text"
                        value={formDescription}
                        onChange={(e) => setFormDescription(e.target.value)}
                        placeholder={t('customEgress.descriptionPlaceholder')}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="col-span-2">
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('customEgress.serverAddress')} <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="text"
                        value={formServer}
                        onChange={(e) => setFormServer(e.target.value)}
                        placeholder={t('customEgress.serverPlaceholder')}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('customEgress.port')}</label>
                      <input
                        type="number"
                        value={formPort}
                        onChange={(e) => setFormPort(parseInt(e.target.value) || 51820)}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">
                      {t('customEgress.clientAddress')} <span className="text-red-400">*</span>
                    </label>
                    <input
                      type="text"
                      value={formAddress}
                      onChange={(e) => setFormAddress(e.target.value)}
                      placeholder={t('customEgress.clientAddressPlaceholder')}
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono placeholder-slate-500 focus:outline-none focus:border-brand"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">
                      {t('customEgress.clientPrivateKey')} <span className="text-red-400">*</span>
                    </label>
                    <input
                      type="password"
                      value={formPrivateKey}
                      onChange={(e) => setFormPrivateKey(e.target.value)}
                      placeholder={t('customEgress.privateKeyPlaceholder')}
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono placeholder-slate-500 focus:outline-none focus:border-brand"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">
                      {t('customEgress.serverPublicKey')} <span className="text-red-400">*</span>
                    </label>
                    <input
                      type="text"
                      value={formPublicKey}
                      onChange={(e) => setFormPublicKey(e.target.value)}
                      placeholder={t('customEgress.publicKeyPlaceholder')}
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono placeholder-slate-500 focus:outline-none focus:border-brand"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">MTU</label>
                      <input
                        type="number"
                        value={formMtu}
                        onChange={(e) => setFormMtu(parseInt(e.target.value) || 1420)}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">DNS</label>
                      <input
                        type="text"
                        value={formDns}
                        onChange={(e) => setFormDns(e.target.value)}
                        placeholder="1.1.1.1"
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">{t('customEgress.preSharedKey')}</label>
                    <input
                      type="password"
                      value={formPreSharedKey}
                      onChange={(e) => setFormPreSharedKey(e.target.value)}
                      placeholder={t('customEgress.preSharedKeyPlaceholder')}
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono placeholder-slate-500 focus:outline-none focus:border-brand"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowAddModal(false);
                  resetForm();
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={handleCreateEgress}
                disabled={actionLoading === "create" || !formTag || !formServer || !formPrivateKey || !formPublicKey || !formAddress}
                className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {actionLoading === "create" ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : (
                  <PlusIcon className="h-4 w-4" />
                )}
                {t('common.add')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Custom Modal */}
      {showEditModal && editingEgress && (
        <div className="fixed inset-0 bg-black/50 flex items-start justify-center z-50 overflow-y-auto">
          <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-2xl m-4">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">{t('customEgress.editTitle', { tag: editingEgress.tag })}</h2>
                <button
                  onClick={() => {
                    setShowEditModal(false);
                    setEditingEgress(null);
                    resetForm();
                  }}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">{t('common.description')}</label>
                <input
                  type="text"
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t('customEgress.serverAddress')}</label>
                  <input
                    type="text"
                    value={formServer}
                    onChange={(e) => setFormServer(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t('customEgress.port')}</label>
                  <input
                    type="number"
                    value={formPort}
                    onChange={(e) => setFormPort(parseInt(e.target.value) || 51820)}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">{t('customEgress.clientAddress')}</label>
                <input
                  type="text"
                  value={formAddress}
                  onChange={(e) => setFormAddress(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">{t('customEgress.clientPrivateKey')}</label>
                <input
                  type="password"
                  value={formPrivateKey}
                  onChange={(e) => setFormPrivateKey(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">{t('customEgress.serverPublicKey')}</label>
                <input
                  type="text"
                  value={formPublicKey}
                  onChange={(e) => setFormPublicKey(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">MTU</label>
                  <input
                    type="number"
                    value={formMtu}
                    onChange={(e) => setFormMtu(parseInt(e.target.value) || 1420)}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">DNS</label>
                  <input
                    type="text"
                    value={formDns}
                    onChange={(e) => setFormDns(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">{t('customEgress.preSharedKey')}</label>
                <input
                  type="password"
                  value={formPreSharedKey}
                  onChange={(e) => setFormPreSharedKey(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-mono placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowEditModal(false);
                  setEditingEgress(null);
                  resetForm();
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={handleUpdateEgress}
                disabled={actionLoading === "update"}
                className="px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {actionLoading === "update" ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : (
                  <CheckIcon className="h-4 w-4" />
                )}
                {t('common.save')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
