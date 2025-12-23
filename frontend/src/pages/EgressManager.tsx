import { useState, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { EgressItem, CustomEgress, WireGuardConfParseResult, PiaRegion, VpnProfile, DirectEgress, OpenVPNEgress, OpenVPNParseResult, V2RayEgress, V2RayURIParseResult, V2RayProtocol, V2RayTransport } from "../types";
import { V2RAY_PROTOCOLS, V2RAY_TRANSPORTS, V2RAY_SECURITY_OPTIONS, V2RAY_TLS_FINGERPRINTS, VLESS_FLOW_OPTIONS } from "../types";
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
  KeyIcon,
  LockClosedIcon,
  ExclamationTriangleIcon,
  ChartBarIcon
} from "@heroicons/react/24/outline";

type TabType = "all" | "pia" | "custom" | "direct" | "openvpn" | "v2ray";
type V2RayImportMethod = "uri" | "manual";
type ImportMethod = "upload" | "paste" | "manual";
type OpenVPNImportMethod = "upload" | "paste" | "manual";

export default function EgressManager() {
  const { t } = useTranslation();
  const [piaEgress, setPiaEgress] = useState<EgressItem[]>([]);
  const [customEgress, setCustomEgress] = useState<CustomEgress[]>([]);
  const [directEgress, setDirectEgress] = useState<DirectEgress[]>([]);
  const [piaProfiles, setPiaProfiles] = useState<VpnProfile[]>([]);
  const [piaRegions, setPiaRegions] = useState<PiaRegion[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("all");

  // Speed test state
  const [speedTestStatus, setSpeedTestStatus] = useState<Record<string, {
    loading: boolean;
    result?: { success: boolean; speed_mbps: number; message: string };
  }>>({});
  const speedTestTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

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

  // Direct egress modal state
  const [showDirectModal, setShowDirectModal] = useState(false);
  const [directModalMode, setDirectModalMode] = useState<"add" | "edit">("add");
  const [editingDirectEgress, setEditingDirectEgress] = useState<DirectEgress | null>(null);
  const [directFormTag, setDirectFormTag] = useState("");
  const [directFormDescription, setDirectFormDescription] = useState("");
  const [directFormBindInterface, setDirectFormBindInterface] = useState("");
  const [directFormInet4Address, setDirectFormInet4Address] = useState("");
  const [directFormInet6Address, setDirectFormInet6Address] = useState("");

  // Direct default (默认直连出口 DNS 配置)
  const [directDefaultDns, setDirectDefaultDns] = useState<string[]>(["1.1.1.1"]);
  const [showDirectDefaultModal, setShowDirectDefaultModal] = useState(false);
  const [directDefaultFormDns, setDirectDefaultFormDns] = useState("");

  // OpenVPN egress state
  const [openvpnEgress, setOpenvpnEgress] = useState<OpenVPNEgress[]>([]);
  const [showOpenvpnModal, setShowOpenvpnModal] = useState(false);
  const [openvpnModalMode, setOpenvpnModalMode] = useState<"add" | "edit">("add");
  const [editingOpenvpnEgress, setEditingOpenvpnEgress] = useState<OpenVPNEgress | null>(null);
  const [openvpnImportMethod, setOpenvpnImportMethod] = useState<OpenVPNImportMethod>("upload");
  const [openvpnPasteContent, setOpenvpnPasteContent] = useState("");
  const [openvpnParsedConfig, setOpenvpnParsedConfig] = useState<OpenVPNParseResult | null>(null);
  const [openvpnParseError, setOpenvpnParseError] = useState<string | null>(null);
  const openvpnFileInputRef = useRef<HTMLInputElement>(null);
  // OpenVPN form fields
  const [openvpnFormTag, setOpenvpnFormTag] = useState("");
  const [openvpnFormDescription, setOpenvpnFormDescription] = useState("");
  const [openvpnFormProtocol, setOpenvpnFormProtocol] = useState<"udp" | "tcp">("udp");
  const [openvpnFormRemoteHost, setOpenvpnFormRemoteHost] = useState("");
  const [openvpnFormRemotePort, setOpenvpnFormRemotePort] = useState(1194);
  const [openvpnFormCaCert, setOpenvpnFormCaCert] = useState("");
  const [openvpnFormClientCert, setOpenvpnFormClientCert] = useState("");
  const [openvpnFormClientKey, setOpenvpnFormClientKey] = useState("");
  const [openvpnFormTlsAuth, setOpenvpnFormTlsAuth] = useState("");
  const [openvpnFormTlsCrypt, setOpenvpnFormTlsCrypt] = useState("");
  const [openvpnFormCrlVerify, setOpenvpnFormCrlVerify] = useState("");
  const [openvpnFormAuthUser, setOpenvpnFormAuthUser] = useState("");
  const [openvpnFormAuthPass, setOpenvpnFormAuthPass] = useState("");
  const [openvpnFormCipher, setOpenvpnFormCipher] = useState("AES-256-GCM");
  const [openvpnFormAuth, setOpenvpnFormAuth] = useState("SHA256");
  const [openvpnFormCompress, setOpenvpnFormCompress] = useState("");
  const [openvpnFormExtraOptions, setOpenvpnFormExtraOptions] = useState("");
  const [showAuthRequiredHint, setShowAuthRequiredHint] = useState(false);
  const [authValidationError, setAuthValidationError] = useState(false);
  const authFieldsRef = useRef<HTMLDivElement>(null);

  // V2Ray egress state
  const [v2rayEgress, setV2rayEgress] = useState<V2RayEgress[]>([]);
  const [showV2rayModal, setShowV2rayModal] = useState(false);
  const [v2rayModalMode, setV2rayModalMode] = useState<"add" | "edit">("add");
  const [editingV2rayEgress, setEditingV2rayEgress] = useState<V2RayEgress | null>(null);
  const [v2rayImportMethod, setV2rayImportMethod] = useState<V2RayImportMethod>("uri");
  const [v2rayUriInput, setV2rayUriInput] = useState("");
  const [v2rayParsedConfig, setV2rayParsedConfig] = useState<V2RayURIParseResult | null>(null);
  const [v2rayParseError, setV2rayParseError] = useState<string | null>(null);
  // V2Ray form fields
  const [v2rayFormTag, setV2rayFormTag] = useState("");
  const [v2rayFormDescription, setV2rayFormDescription] = useState("");
  const [v2rayFormProtocol, setV2rayFormProtocol] = useState<V2RayProtocol>("vless");
  const [v2rayFormServer, setV2rayFormServer] = useState("");
  const [v2rayFormPort, setV2rayFormPort] = useState(443);
  const [v2rayFormUuid, setV2rayFormUuid] = useState("");
  const [v2rayFormPassword, setV2rayFormPassword] = useState("");
  const [v2rayFormSecurity, setV2rayFormSecurity] = useState("auto");
  const [v2rayFormAlterId, setV2rayFormAlterId] = useState(0);
  const [v2rayFormFlow, setV2rayFormFlow] = useState("");
  const [v2rayFormTlsEnabled, setV2rayFormTlsEnabled] = useState(true);
  const [v2rayFormTlsSni, setV2rayFormTlsSni] = useState("");
  const [v2rayFormTlsFingerprint, setV2rayFormTlsFingerprint] = useState("");
  const [v2rayFormTlsAllowInsecure, setV2rayFormTlsAllowInsecure] = useState(false);
  // REALITY
  const [v2rayFormRealityEnabled, setV2rayFormRealityEnabled] = useState(false);
  const [v2rayFormRealityPublicKey, setV2rayFormRealityPublicKey] = useState("");
  const [v2rayFormRealityShortId, setV2rayFormRealityShortId] = useState("");
  const [v2rayFormTransportType, setV2rayFormTransportType] = useState<V2RayTransport>("tcp");
  const [v2rayFormTransportPath, setV2rayFormTransportPath] = useState("");
  const [v2rayFormTransportHost, setV2rayFormTransportHost] = useState("");
  const [v2rayFormTransportServiceName, setV2rayFormTransportServiceName] = useState("");

  const loadEgress = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [allData, customData, profilesData, directData, openvpnData, v2rayData, directDefaultData] = await Promise.all([
        api.getAllEgress(),
        api.getCustomEgress(),
        api.getProfiles(),
        api.getDirectEgress(),
        api.getOpenVPNEgress(),
        api.getV2RayEgress(),
        api.getDirectDefault()
      ]);
      setPiaEgress(allData.pia);
      setCustomEgress(customData.egress);
      setPiaProfiles(profilesData.profiles);
      setDirectEgress(directData.egress);
      setOpenvpnEgress(openvpnData.egress);
      setV2rayEgress(v2rayData.egress);
      setDirectDefaultDns(directDefaultData.dns_servers);
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

  // 清理测速定时器
  useEffect(() => {
    return () => {
      Object.values(speedTestTimers.current).forEach(timer => clearTimeout(timer));
    };
  }, []);

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

  const resetDirectForm = () => {
    setDirectFormTag("");
    setDirectFormDescription("");
    setDirectFormBindInterface("");
    setDirectFormInet4Address("");
    setDirectFormInet6Address("");
    setEditingDirectEgress(null);
  };

  const resetOpenvpnForm = () => {
    setOpenvpnFormTag("");
    setOpenvpnFormDescription("");
    setOpenvpnFormProtocol("udp");
    setOpenvpnFormRemoteHost("");
    setOpenvpnFormRemotePort(1194);
    setOpenvpnFormCaCert("");
    setOpenvpnFormClientCert("");
    setOpenvpnFormClientKey("");
    setOpenvpnFormTlsAuth("");
    setOpenvpnFormTlsCrypt("");
    setOpenvpnFormCrlVerify("");
    setOpenvpnFormAuthUser("");
    setOpenvpnFormAuthPass("");
    setOpenvpnFormCipher("AES-256-GCM");
    setOpenvpnFormAuth("SHA256");
    setOpenvpnFormCompress("");
    setOpenvpnFormExtraOptions("");
    setOpenvpnParsedConfig(null);
    setOpenvpnPasteContent("");
    setOpenvpnParseError(null);
    setEditingOpenvpnEgress(null);
    setOpenvpnImportMethod("upload");
    setShowAuthRequiredHint(false);
    setAuthValidationError(false);
  };

  const resetV2rayForm = () => {
    setV2rayFormTag("");
    setV2rayFormDescription("");
    setV2rayFormProtocol("vless");
    setV2rayFormServer("");
    setV2rayFormPort(443);
    setV2rayFormUuid("");
    setV2rayFormPassword("");
    setV2rayFormSecurity("auto");
    setV2rayFormAlterId(0);
    setV2rayFormFlow("");
    setV2rayFormTlsEnabled(true);
    setV2rayFormTlsSni("");
    setV2rayFormTlsFingerprint("");
    setV2rayFormTlsAllowInsecure(false);
    // REALITY
    setV2rayFormRealityEnabled(false);
    setV2rayFormRealityPublicKey("");
    setV2rayFormRealityShortId("");
    setV2rayFormTransportType("tcp");
    setV2rayFormTransportPath("");
    setV2rayFormTransportHost("");
    setV2rayFormTransportServiceName("");
    setV2rayParsedConfig(null);
    setV2rayUriInput("");
    setV2rayParseError(null);
    setEditingV2rayEgress(null);
    setV2rayImportMethod("uri");
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
    if (!piaFormTag || !piaFormRegionId) return;

    setActionLoading("create-pia");
    try {
      // Use tag as description if not provided
      const description = piaFormDescription || piaFormTag;
      await api.createProfile(piaFormTag, description, piaFormRegionId);
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

  // ============ Speed Test ============

  const handleSpeedTest = async (tag: string) => {
    // 取消之前的定时器
    if (speedTestTimers.current[tag]) {
      clearTimeout(speedTestTimers.current[tag]);
      delete speedTestTimers.current[tag];
    }

    setSpeedTestStatus(prev => ({
      ...prev,
      [tag]: { loading: true }
    }));

    try {
      const result = await api.testEgressSpeed(tag, 10, 30);
      setSpeedTestStatus(prev => ({
        ...prev,
        [tag]: { loading: false, result }
      }));

      // 10秒后清除结果
      speedTestTimers.current[tag] = setTimeout(() => {
        setSpeedTestStatus(prev => {
          const next = { ...prev };
          delete next[tag];
          return next;
        });
        delete speedTestTimers.current[tag];
      }, 10000);
    } catch (err) {
      setSpeedTestStatus(prev => ({
        ...prev,
        [tag]: {
          loading: false,
          result: { success: false, speed_mbps: 0, message: err instanceof Error ? err.message : t('egress.speedTestFailed') }
        }
      }));

      // 5秒后清除错误结果
      speedTestTimers.current[tag] = setTimeout(() => {
        setSpeedTestStatus(prev => {
          const next = { ...prev };
          delete next[tag];
          return next;
        });
        delete speedTestTimers.current[tag];
      }, 5000);
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
    if (!(pasteContent || "").trim()) {
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
    if (!(formTag || "").trim() || !(formServer || "").trim() || !(formPrivateKey || "").trim() || !(formPublicKey || "").trim() || !(formAddress || "").trim()) {
      setError(t('customEgress.fillAllFieldsError'));
      return;
    }

    setActionLoading("create");
    try {
      await api.createCustomEgress({
        tag: (formTag || "").trim(),
        description: (formDescription || "").trim(),
        server: (formServer || "").trim(),
        port: formPort,
        private_key: (formPrivateKey || "").trim(),
        public_key: (formPublicKey || "").trim(),
        address: (formAddress || "").trim(),
        mtu: formMtu,
        dns: (formDns || "").trim(),
        pre_shared_key: (formPreSharedKey || "").trim() || undefined
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
    setFormTag(egress.tag || "");
    setFormDescription(egress.description || "");
    setFormServer(egress.server || "");
    setFormPort(egress.port || 51820);
    setFormPrivateKey(egress.private_key || "");
    setFormPublicKey(egress.public_key || "");
    setFormAddress(egress.address || "");
    setFormMtu(egress.mtu || 1420);
    setFormDns(egress.dns || "");
    setFormPreSharedKey(egress.pre_shared_key || "");
    setShowEditModal(true);
  };

  const handleUpdateEgress = async () => {
    if (!editingEgress) return;

    setActionLoading("update");
    try {
      await api.updateCustomEgress(editingEgress.tag, {
        description: (formDescription || "").trim(),
        server: (formServer || "").trim(),
        port: formPort,
        private_key: (formPrivateKey || "").trim(),
        public_key: (formPublicKey || "").trim(),
        address: (formAddress || "").trim(),
        mtu: formMtu,
        dns: (formDns || "").trim(),
        pre_shared_key: (formPreSharedKey || "").trim() || undefined
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

  // ============ Direct Egress Management ============

  const handleAddDirectEgress = () => {
    resetDirectForm();
    setDirectModalMode("add");
    setShowDirectModal(true);
  };

  const handleEditDirectEgress = (egress: DirectEgress) => {
    setEditingDirectEgress(egress);
    setDirectFormTag(egress.tag);
    setDirectFormDescription(egress.description || "");
    setDirectFormBindInterface(egress.bind_interface || "");
    setDirectFormInet4Address(egress.inet4_bind_address || "");
    setDirectFormInet6Address(egress.inet6_bind_address || "");
    setDirectModalMode("edit");
    setShowDirectModal(true);
  };

  const handleCreateDirectEgress = async () => {
    if (!directFormTag) return;
    if (!directFormBindInterface && !directFormInet4Address && !directFormInet6Address) {
      setError(t('directEgress.bindRequiredError'));
      return;
    }

    setActionLoading("create-direct");
    try {
      await api.createDirectEgress({
        tag: directFormTag,
        description: directFormDescription,
        bind_interface: directFormBindInterface || undefined,
        inet4_bind_address: directFormInet4Address || undefined,
        inet6_bind_address: directFormInet6Address || undefined
      });
      setSuccessMessage(t('directEgress.createSuccess', { tag: directFormTag }));
      setShowDirectModal(false);
      resetDirectForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.createFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleUpdateDirectEgress = async () => {
    if (!editingDirectEgress) return;

    setActionLoading("update-direct");
    try {
      await api.updateDirectEgress(editingDirectEgress.tag, {
        description: directFormDescription,
        bind_interface: directFormBindInterface || undefined,
        inet4_bind_address: directFormInet4Address || undefined,
        inet6_bind_address: directFormInet6Address || undefined
      });
      setSuccessMessage(t('directEgress.updateSuccess', { tag: editingDirectEgress.tag }));
      setShowDirectModal(false);
      resetDirectForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.updateFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteDirectEgress = async (tag: string) => {
    if (!confirm(t('directEgress.confirmDelete', { tag }))) return;

    setActionLoading(`delete-direct-${tag}`);
    try {
      await api.deleteDirectEgress(tag);
      setSuccessMessage(t('directEgress.deleteSuccess', { tag }));
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.deleteFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  // ============ Direct Default DNS Management ============

  const handleEditDirectDefault = () => {
    setDirectDefaultFormDns(directDefaultDns.join(", "));
    setShowDirectDefaultModal(true);
  };

  const handleSaveDirectDefault = async () => {
    const dnsServers = (directDefaultFormDns || "")
      .split(/[,\s]+/)
      .map(s => (s || "").trim())
      .filter(s => s.length > 0);

    if (dnsServers.length === 0) {
      setError(t('directDefault.dnsRequired'));
      return;
    }

    setActionLoading("save-direct-default");
    try {
      await api.updateDirectDefault(dnsServers);
      setDirectDefaultDns(dnsServers);
      setSuccessMessage(t('directDefault.saveSuccess'));
      setShowDirectDefaultModal(false);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.saveFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  // ============ OpenVPN Egress Management ============

  const handleAddOpenvpnEgress = () => {
    resetOpenvpnForm();
    setOpenvpnModalMode("add");
    setShowOpenvpnModal(true);
  };

  const handleEditOpenvpnEgress = (egress: OpenVPNEgress) => {
    setEditingOpenvpnEgress(egress);
    setOpenvpnFormTag(egress.tag);
    setOpenvpnFormDescription(egress.description || "");
    setOpenvpnFormProtocol(egress.protocol);
    setOpenvpnFormRemoteHost(egress.remote_host);
    setOpenvpnFormRemotePort(egress.remote_port);
    setOpenvpnFormCaCert(egress.ca_cert);
    setOpenvpnFormClientCert(egress.client_cert || "");
    // client_key 被 API 掩码为 [hidden]，不填充
    setOpenvpnFormClientKey("");
    setOpenvpnFormTlsAuth(egress.tls_auth || "");
    setOpenvpnFormTlsCrypt(egress.tls_crypt || "");
    setOpenvpnFormCrlVerify(egress.crl_verify || "");
    setOpenvpnFormAuthUser(egress.auth_user || "");
    // auth_pass 被 API 掩码为 ***，不填充，留空表示不修改
    setOpenvpnFormAuthPass("");
    setOpenvpnFormCipher(egress.cipher);
    setOpenvpnFormAuth(egress.auth);
    setOpenvpnFormCompress(egress.compress || "");
    setOpenvpnFormExtraOptions(egress.extra_options || "");
    setOpenvpnModalMode("edit");
    setShowOpenvpnModal(true);
  };

  const handleOpenvpnFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const content = await file.text();
      await parseOpenvpnConfig(content);
      const baseName = file.name.replace(/\.(ovpn|conf)$/i, "").toLowerCase().replace(/[^a-z0-9-]/g, "-");
      setOpenvpnFormTag(baseName);
    } catch (err) {
      setOpenvpnParseError(err instanceof Error ? err.message : t('openvpnEgress.parseFailed'));
    }
  };

  const parseOpenvpnConfig = async (content: string) => {
    try {
      setOpenvpnParseError(null);
      const result = await api.parseOpenVPNConfig(content);
      setOpenvpnParsedConfig(result);
      if (result.protocol) setOpenvpnFormProtocol(result.protocol as "udp" | "tcp");
      if (result.remote_host) setOpenvpnFormRemoteHost(result.remote_host);
      if (result.remote_port) setOpenvpnFormRemotePort(result.remote_port);
      if (result.ca_cert) setOpenvpnFormCaCert(result.ca_cert);
      if (result.client_cert) setOpenvpnFormClientCert(result.client_cert);
      if (result.client_key) setOpenvpnFormClientKey(result.client_key);
      if (result.tls_auth) setOpenvpnFormTlsAuth(result.tls_auth);
      if (result.tls_crypt) setOpenvpnFormTlsCrypt(result.tls_crypt);
      if (result.crl_verify) setOpenvpnFormCrlVerify(result.crl_verify);
      // cipher 和 auth 需要转换为大写以匹配下拉选项
      if (result.cipher) setOpenvpnFormCipher(result.cipher.toUpperCase());
      if (result.auth) setOpenvpnFormAuth(result.auth.toUpperCase());
      if (result.compress) setOpenvpnFormCompress(result.compress);
      // 检测是否需要用户名/密码认证
      setShowAuthRequiredHint(!!result.requires_auth);
      // 解析成功后自动切换到手动输入模式，让用户可以看到并编辑解析后的数据
      setOpenvpnImportMethod("manual");
      setSuccessMessage(t('openvpnEgress.parseSuccess'));
      setTimeout(() => setSuccessMessage(null), 2000);
    } catch (err) {
      setOpenvpnParseError(err instanceof Error ? err.message : t('openvpnEgress.parseFailed'));
    }
  };

  const handleCreateOpenvpnEgress = async (forceCreate = false) => {
    if (!openvpnFormTag || !openvpnFormRemoteHost || !openvpnFormCaCert) {
      setError(t('openvpnEgress.fillRequiredFields'));
      return;
    }

    // 检查是否需要认证但未填写
    if (showAuthRequiredHint && !forceCreate && (!openvpnFormAuthUser || !openvpnFormAuthPass)) {
      setAuthValidationError(true);
      // 滚动到认证字段
      authFieldsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }

    setAuthValidationError(false);
    setActionLoading("create-openvpn");
    try {
      await api.createOpenVPNEgress({
        tag: openvpnFormTag,
        description: openvpnFormDescription,
        protocol: openvpnFormProtocol,
        remote_host: openvpnFormRemoteHost,
        remote_port: openvpnFormRemotePort,
        ca_cert: openvpnFormCaCert,
        client_cert: openvpnFormClientCert || undefined,
        client_key: openvpnFormClientKey || undefined,
        tls_auth: openvpnFormTlsAuth || undefined,
        tls_crypt: openvpnFormTlsCrypt || undefined,
        crl_verify: openvpnFormCrlVerify || undefined,
        auth_user: openvpnFormAuthUser || undefined,
        auth_pass: openvpnFormAuthPass || undefined,
        cipher: openvpnFormCipher,
        auth: openvpnFormAuth,
        compress: openvpnFormCompress || undefined,
        extra_options: openvpnFormExtraOptions || undefined
      });
      setSuccessMessage(t('openvpnEgress.createSuccess', { tag: openvpnFormTag }));
      setShowOpenvpnModal(false);
      resetOpenvpnForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.createFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleUpdateOpenvpnEgress = async () => {
    if (!editingOpenvpnEgress) return;

    setActionLoading("update-openvpn");
    try {
      await api.updateOpenVPNEgress(editingOpenvpnEgress.tag, {
        description: openvpnFormDescription,
        protocol: openvpnFormProtocol,
        remote_host: openvpnFormRemoteHost,
        remote_port: openvpnFormRemotePort,
        ca_cert: openvpnFormCaCert,
        client_cert: openvpnFormClientCert || undefined,
        client_key: openvpnFormClientKey || undefined,
        tls_auth: openvpnFormTlsAuth || undefined,
        tls_crypt: openvpnFormTlsCrypt || undefined,
        crl_verify: openvpnFormCrlVerify || undefined,
        auth_user: openvpnFormAuthUser || undefined,
        auth_pass: openvpnFormAuthPass || undefined,
        cipher: openvpnFormCipher,
        auth: openvpnFormAuth,
        compress: openvpnFormCompress || undefined,
        extra_options: openvpnFormExtraOptions || undefined
      });
      setSuccessMessage(t('openvpnEgress.updateSuccess', { tag: editingOpenvpnEgress.tag }));
      setShowOpenvpnModal(false);
      resetOpenvpnForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.updateFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteOpenvpnEgress = async (tag: string) => {
    if (!confirm(t('openvpnEgress.confirmDelete', { tag }))) return;

    setActionLoading(`delete-openvpn-${tag}`);
    try {
      await api.deleteOpenVPNEgress(tag);
      setSuccessMessage(t('openvpnEgress.deleteSuccess', { tag }));
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.deleteFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  // ============ V2Ray Egress Management ============

  const handleAddV2rayEgress = () => {
    resetV2rayForm();
    setV2rayModalMode("add");
    setShowV2rayModal(true);
  };

  const handleEditV2rayEgress = (egress: V2RayEgress) => {
    setEditingV2rayEgress(egress);
    setV2rayFormTag(egress.tag);
    setV2rayFormDescription(egress.description || "");
    setV2rayFormProtocol(egress.protocol);
    setV2rayFormServer(egress.server);
    setV2rayFormPort(egress.server_port);
    setV2rayFormUuid(egress.uuid || "");
    // password is masked as *** by API, don't populate
    setV2rayFormPassword("");
    setV2rayFormSecurity(egress.security || "auto");
    setV2rayFormAlterId(egress.alter_id || 0);
    setV2rayFormFlow(egress.flow || "");
    setV2rayFormTlsEnabled(egress.tls_enabled === 1);
    setV2rayFormTlsSni(egress.tls_sni || "");
    setV2rayFormTlsFingerprint(egress.tls_fingerprint || "");
    setV2rayFormTlsAllowInsecure(egress.tls_allow_insecure === 1);
    // REALITY
    setV2rayFormRealityEnabled(egress.reality_enabled === 1);
    setV2rayFormRealityPublicKey(egress.reality_public_key || "");
    setV2rayFormRealityShortId(egress.reality_short_id || "");
    setV2rayFormTransportType(egress.transport_type);
    // Parse transport config if available
    if (egress.transport_config) {
      try {
        const config = typeof egress.transport_config === "string"
          ? JSON.parse(egress.transport_config)
          : egress.transport_config;
        setV2rayFormTransportPath(config.path || "");
        setV2rayFormTransportHost(config.host || "");
        setV2rayFormTransportServiceName(config.service_name || "");
      } catch {
        // ignore parse errors
      }
    }
    setV2rayModalMode("edit");
    setShowV2rayModal(true);
  };

  const parseV2rayUri = async (uri: string) => {
    try {
      setV2rayParseError(null);
      const result = await api.parseV2RayURI(uri);
      setV2rayParsedConfig(result);
      // Populate form fields from parsed result
      if (result.protocol) setV2rayFormProtocol(result.protocol);
      if (result.server) setV2rayFormServer(result.server);
      if (result.server_port) setV2rayFormPort(result.server_port);
      if (result.uuid) setV2rayFormUuid(result.uuid);
      if (result.password) setV2rayFormPassword(result.password);
      if (result.security) setV2rayFormSecurity(result.security);
      if (result.alter_id !== undefined) setV2rayFormAlterId(result.alter_id);
      if (result.flow) setV2rayFormFlow(result.flow);
      if (result.tls_enabled !== undefined) setV2rayFormTlsEnabled(result.tls_enabled);
      if (result.tls_sni) setV2rayFormTlsSni(result.tls_sni);
      if (result.tls_fingerprint) setV2rayFormTlsFingerprint(result.tls_fingerprint);
      if (result.tls_allow_insecure !== undefined) setV2rayFormTlsAllowInsecure(result.tls_allow_insecure);
      // REALITY
      if (result.reality_enabled !== undefined) setV2rayFormRealityEnabled(result.reality_enabled);
      if (result.reality_public_key) setV2rayFormRealityPublicKey(result.reality_public_key);
      if (result.reality_short_id) setV2rayFormRealityShortId(result.reality_short_id);
      if (result.transport_type) setV2rayFormTransportType(result.transport_type);
      if (result.transport_config?.path) setV2rayFormTransportPath(result.transport_config.path);
      if (result.transport_config?.host) setV2rayFormTransportHost(result.transport_config.host);
      if (result.transport_config?.service_name) setV2rayFormTransportServiceName(result.transport_config.service_name);
      // Generate tag from remark or server
      if (result.remark) {
        setV2rayFormTag(result.remark.toLowerCase().replace(/[^a-z0-9-]/g, "-"));
      } else if (result.server) {
        setV2rayFormTag(result.server.split(".")[0].toLowerCase().replace(/[^a-z0-9-]/g, "-"));
      }
      // Switch to manual mode to show parsed data
      setV2rayImportMethod("manual");
      setSuccessMessage(t('v2rayEgress.parseSuccess'));
      setTimeout(() => setSuccessMessage(null), 2000);
    } catch (err) {
      setV2rayParseError(err instanceof Error ? err.message : t('v2rayEgress.parseFailed'));
    }
  };

  const handleCreateV2rayEgress = async () => {
    if (!v2rayFormTag || !v2rayFormServer) {
      setError(t('v2rayEgress.fillRequiredFields'));
      return;
    }

    // Validate auth based on protocol
    if (v2rayFormProtocol === "trojan" && !v2rayFormPassword) {
      setError(t('v2rayEgress.passwordRequired'));
      return;
    }
    if ((v2rayFormProtocol === "vmess" || v2rayFormProtocol === "vless") && !v2rayFormUuid) {
      setError(t('v2rayEgress.uuidRequired'));
      return;
    }

    setActionLoading("create-v2ray");
    try {
      // Build transport config
      const transportConfig: Record<string, string> = {};
      if (v2rayFormTransportPath) transportConfig.path = v2rayFormTransportPath;
      if (v2rayFormTransportHost) transportConfig.host = v2rayFormTransportHost;
      if (v2rayFormTransportServiceName) transportConfig.service_name = v2rayFormTransportServiceName;

      await api.createV2RayEgress({
        tag: v2rayFormTag,
        description: v2rayFormDescription,
        protocol: v2rayFormProtocol,
        server: v2rayFormServer,
        server_port: v2rayFormPort,
        uuid: v2rayFormUuid || undefined,
        password: v2rayFormPassword || undefined,
        security: v2rayFormSecurity,
        alter_id: v2rayFormAlterId,
        flow: v2rayFormFlow || undefined,
        tls_enabled: v2rayFormTlsEnabled,
        tls_sni: v2rayFormTlsSni || undefined,
        tls_fingerprint: v2rayFormTlsFingerprint || undefined,
        tls_allow_insecure: v2rayFormTlsAllowInsecure,
        // REALITY
        reality_enabled: v2rayFormRealityEnabled,
        reality_public_key: v2rayFormRealityPublicKey || undefined,
        reality_short_id: v2rayFormRealityShortId || undefined,
        transport_type: v2rayFormTransportType,
        transport_config: Object.keys(transportConfig).length > 0 ? transportConfig : undefined
      });
      setSuccessMessage(t('v2rayEgress.createSuccess', { tag: v2rayFormTag }));
      setShowV2rayModal(false);
      resetV2rayForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.createFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleUpdateV2rayEgress = async () => {
    if (!editingV2rayEgress) return;

    setActionLoading("update-v2ray");
    try {
      // Build transport config
      const transportConfig: Record<string, string> = {};
      if (v2rayFormTransportPath) transportConfig.path = v2rayFormTransportPath;
      if (v2rayFormTransportHost) transportConfig.host = v2rayFormTransportHost;
      if (v2rayFormTransportServiceName) transportConfig.service_name = v2rayFormTransportServiceName;

      await api.updateV2RayEgress(editingV2rayEgress.tag, {
        description: v2rayFormDescription,
        protocol: v2rayFormProtocol,
        server: v2rayFormServer,
        server_port: v2rayFormPort,
        uuid: v2rayFormUuid || undefined,
        password: v2rayFormPassword || undefined,
        security: v2rayFormSecurity,
        alter_id: v2rayFormAlterId,
        flow: v2rayFormFlow || undefined,
        tls_enabled: v2rayFormTlsEnabled,
        tls_sni: v2rayFormTlsSni || undefined,
        tls_fingerprint: v2rayFormTlsFingerprint || undefined,
        tls_allow_insecure: v2rayFormTlsAllowInsecure,
        // REALITY
        reality_enabled: v2rayFormRealityEnabled,
        reality_public_key: v2rayFormRealityPublicKey || undefined,
        reality_short_id: v2rayFormRealityShortId || undefined,
        transport_type: v2rayFormTransportType,
        transport_config: Object.keys(transportConfig).length > 0 ? transportConfig : undefined
      });
      setSuccessMessage(t('v2rayEgress.updateSuccess', { tag: editingV2rayEgress.tag }));
      setShowV2rayModal(false);
      resetV2rayForm();
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.updateFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteV2rayEgress = async (tag: string) => {
    if (!confirm(t('v2rayEgress.confirmDelete', { tag }))) return;

    setActionLoading(`delete-v2ray-${tag}`);
    try {
      await api.deleteV2RayEgress(tag);
      setSuccessMessage(t('v2rayEgress.deleteSuccess', { tag }));
      loadEgress();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.deleteFailed'));
    } finally {
      setActionLoading(null);
    }
  };

  const getV2rayProtocolLabel = (protocol: V2RayProtocol) => {
    const p = V2RAY_PROTOCOLS.find(p => p.value === protocol);
    return p ? p.label : protocol.toUpperCase();
  };

  const getV2rayTransportLabel = (transport: V2RayTransport) => {
    const t = V2RAY_TRANSPORTS.find(t => t.value === transport);
    return t ? t.label : transport.toUpperCase();
  };

  const filteredPia = activeTab === "custom" || activeTab === "direct" || activeTab === "openvpn" || activeTab === "v2ray" ? [] : piaProfiles;
  const filteredCustom = activeTab === "pia" || activeTab === "direct" || activeTab === "openvpn" || activeTab === "v2ray" ? [] : customEgress;
  const filteredDirect = activeTab === "pia" || activeTab === "custom" || activeTab === "openvpn" || activeTab === "v2ray" ? [] : directEgress;
  const filteredOpenvpn = activeTab === "pia" || activeTab === "custom" || activeTab === "direct" || activeTab === "v2ray" ? [] : openvpnEgress;
  const filteredV2ray = activeTab === "pia" || activeTab === "custom" || activeTab === "direct" || activeTab === "openvpn" ? [] : v2rayEgress;
  const totalCount = piaProfiles.length + customEgress.length + directEgress.length + 1 + openvpnEgress.length + v2rayEgress.length; // +1 for default direct

  if (loading && !piaProfiles.length && !customEgress.length && !directEgress.length && !openvpnEgress.length) {
    return (
      <div className="flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-brand border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-[calc(100vh-12rem)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4 md:mb-6">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-white">{t('egress.title')}</h1>
          <p className="text-xs md:text-sm text-slate-400 mt-1">{t('egress.subtitle')}</p>
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
      {showLoginModal && createPortal(
        <div className="fixed inset-0 bg-black/60 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
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
        </div>,
        document.body
      )}

      {/* Tabs - Horizontal scroll on mobile */}
      <div className="flex gap-2 border-b border-white/10 pb-2 mb-4 md:mb-6 overflow-x-auto scrollbar-hide">
        {[
          { key: "all", label: `${t('common.all')} (${totalCount})` },
          { key: "pia", label: `${t('egress.pia')} (${piaProfiles.length})` },
          { key: "custom", label: `${t('egress.custom')} (${customEgress.length})` },
          { key: "direct", label: `${t('egress.direct')} (${directEgress.length + 1})` },
          { key: "openvpn", label: `${t('egress.openvpn')} (${openvpnEgress.length})` },
          { key: "v2ray", label: `V2Ray (${v2rayEgress.length})` }
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as TabType)}
            className={`px-3 md:px-4 py-2 text-xs md:text-sm font-medium rounded-lg transition-colors whitespace-nowrap flex-shrink-0 ${
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
      {/* Empty state - exclude "all" and "direct" tabs since they always have the default direct card */}
      {filteredPia.length === 0 && filteredCustom.length === 0 && filteredDirect.length === 0 && filteredOpenvpn.length === 0 && filteredV2ray.length === 0 && activeTab !== "all" && activeTab !== "direct" ? (
        <div className="flex-1 rounded-xl bg-white/5 border border-white/10 p-12 text-center flex flex-col items-center justify-center">
          <GlobeAltIcon className="h-12 w-12 text-slate-600 mb-4" />
          <p className="text-slate-400">
            {activeTab === "custom" ? t('egress.noCustomEgress') : activeTab === "pia" ? t('egress.noPiaLines') : activeTab === "openvpn" ? t('openvpnEgress.noOpenvpnEgress') : activeTab === "v2ray" ? t('v2rayEgress.noV2rayEgress') : t('egress.noEgressFound')}
          </p>
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
              {activeTab === "openvpn" && (
                <button
                  onClick={handleAddOpenvpnEgress}
                  className="px-4 py-2 rounded-lg bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium"
                >
                  {t('openvpnEgress.addOpenvpnEgress')}
                </button>
              )}
              {activeTab === "v2ray" && (
                <button
                  onClick={handleAddV2rayEgress}
                  className="px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-600 text-white text-sm font-medium"
                >
                  {t('v2rayEgress.addV2rayEgress')}
                </button>
              )}
          </div>
        </div>
      ) : (
        <div className="flex-1 rounded-xl bg-white/5 border border-white/10 p-4 md:p-6 space-y-4 md:space-y-6 overflow-y-auto">
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
                      <div className="flex gap-1 flex-shrink-0">
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

                    <div className="mt-3 flex gap-2">
                      <button
                        onClick={() => handleReconnectPiaProfile(profile.tag)}
                        disabled={actionLoading === `reconnect-${profile.tag}`}
                        className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-slate-800/50 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 transition-colors"
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
                      <button
                        onClick={() => handleSpeedTest(profile.tag)}
                        disabled={speedTestStatus[profile.tag]?.loading}
                        className={`flex-1 flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                          speedTestStatus[profile.tag]?.result
                            ? speedTestStatus[profile.tag].result?.success
                              ? "bg-emerald-500/20 text-emerald-400"
                              : "bg-red-500/20 text-red-400"
                            : "bg-slate-800/50 text-slate-300 hover:bg-slate-700"
                        }`}
                      >
                        {speedTestStatus[profile.tag]?.loading ? (
                          <>
                            <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                            {t('egress.speedTesting')}
                          </>
                        ) : speedTestStatus[profile.tag]?.result ? (
                          <>
                            {speedTestStatus[profile.tag].result?.success ? (
                              <CheckCircleIcon className="h-3.5 w-3.5" />
                            ) : (
                              <XCircleIcon className="h-3.5 w-3.5" />
                            )}
                            {speedTestStatus[profile.tag].result?.message}
                          </>
                        ) : (
                          <>
                            <ChartBarIcon className="h-3.5 w-3.5" />
                            {t('egress.speedTest')}
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
                      <div className="flex gap-1 flex-shrink-0">
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

                    <div className="mt-3">
                      <button
                        onClick={() => handleSpeedTest(egress.tag)}
                        disabled={speedTestStatus[egress.tag]?.loading}
                        className={`w-full flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                          speedTestStatus[egress.tag]?.result
                            ? speedTestStatus[egress.tag].result?.success
                              ? "bg-emerald-500/20 text-emerald-400"
                              : "bg-red-500/20 text-red-400"
                            : "bg-slate-800/50 text-slate-300 hover:bg-slate-700"
                        }`}
                      >
                        {speedTestStatus[egress.tag]?.loading ? (
                          <>
                            <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                            {t('egress.speedTesting')}
                          </>
                        ) : speedTestStatus[egress.tag]?.result ? (
                          <>
                            {speedTestStatus[egress.tag].result?.success ? (
                              <CheckCircleIcon className="h-3.5 w-3.5" />
                            ) : (
                              <XCircleIcon className="h-3.5 w-3.5" />
                            )}
                            {speedTestStatus[egress.tag].result?.message}
                          </>
                        ) : (
                          <>
                            <ChartBarIcon className="h-3.5 w-3.5" />
                            {t('egress.speedTest')}
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Direct Egress */}
          {(activeTab === "all" || activeTab === "direct") && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
                  <GlobeAltIcon className="h-4 w-4" />
                  {t('directEgress.title')} ({filteredDirect.length + 1})
                </h3>
                {activeTab === "direct" && (
                  <button
                    onClick={handleAddDirectEgress}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 text-xs font-medium transition-colors"
                  >
                    <PlusIcon className="h-3.5 w-3.5" />
                    {t('directEgress.addEgress')}
                  </button>
                )}
              </div>
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                {/* Default Direct Egress Card */}
                <div className="rounded-xl border p-4 bg-emerald-500/5 border-emerald-500/20">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-emerald-500/20">
                        <GlobeAltIcon className="h-5 w-5 text-emerald-400" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="font-semibold text-white">direct</h4>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/20 text-emerald-400">
                            {t('directDefault.default')}
                          </span>
                        </div>
                        <p className="text-xs text-slate-500">{t('directDefault.description')}</p>
                      </div>
                    </div>
                    <button
                      onClick={handleEditDirectDefault}
                      className="p-1.5 rounded-lg text-slate-400 hover:bg-white/10 hover:text-white"
                      title={t('common.edit')}
                    >
                      <PencilIcon className="h-4 w-4" />
                    </button>
                  </div>

                  <div className="mt-3 pt-3 border-t border-white/5 space-y-1">
                    <p className="text-xs text-slate-400">
                      <span className="text-slate-500">DNS:</span>{" "}
                      <span className="font-mono">{directDefaultDns.join(", ")}</span>
                    </p>
                  </div>

                  <div className="mt-3">
                    <button
                      onClick={() => handleSpeedTest("direct")}
                      disabled={speedTestStatus["direct"]?.loading}
                      className={`w-full flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                        speedTestStatus["direct"]?.result
                          ? speedTestStatus["direct"].result?.success
                            ? "bg-emerald-500/20 text-emerald-400"
                            : "bg-red-500/20 text-red-400"
                          : "bg-slate-800/50 text-slate-300 hover:bg-slate-700"
                      }`}
                    >
                      {speedTestStatus["direct"]?.loading ? (
                        <>
                          <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                          {t('egress.speedTesting')}
                        </>
                      ) : speedTestStatus["direct"]?.result ? (
                        <>
                          {speedTestStatus["direct"].result?.success ? (
                            <CheckCircleIcon className="h-3.5 w-3.5" />
                          ) : (
                            <XCircleIcon className="h-3.5 w-3.5" />
                          )}
                          {speedTestStatus["direct"].result?.message}
                        </>
                      ) : (
                        <>
                          <ChartBarIcon className="h-3.5 w-3.5" />
                          {t('egress.speedTest')}
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Custom Direct Egress Cards */}
                {filteredDirect.map((egress) => (
                  <div
                    key={egress.tag}
                    className={`rounded-xl border p-4 ${egress.enabled ? "bg-cyan-500/5 border-cyan-500/20" : "bg-white/5 border-white/10 opacity-50"}`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${egress.enabled ? "bg-cyan-500/20" : "bg-white/10"}`}>
                          <GlobeAltIcon className={`h-5 w-5 ${egress.enabled ? "text-cyan-400" : "text-slate-400"}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-semibold text-white">{egress.tag}</h4>
                            {egress.enabled ? (
                              <CheckCircleIcon className="h-4 w-4 text-cyan-400" />
                            ) : (
                              <XCircleIcon className="h-4 w-4 text-slate-500" />
                            )}
                          </div>
                          <p className="text-xs text-slate-500">{egress.description || t('directEgress.defaultDescription')}</p>
                        </div>
                      </div>
                      <div className="flex gap-1 flex-shrink-0">
                        <button
                          onClick={() => handleEditDirectEgress(egress)}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-white/10 hover:text-white"
                          title={t('common.edit')}
                        >
                          <PencilIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteDirectEgress(egress.tag)}
                          disabled={actionLoading === `delete-direct-${egress.tag}`}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                          title={t('common.delete')}
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>

                    <div className="mt-3 pt-3 border-t border-white/5 space-y-1">
                      {egress.bind_interface && (
                        <p className="text-xs text-slate-400">
                          <span className="text-slate-500">{t('directEgress.interface')}:</span> {egress.bind_interface}
                        </p>
                      )}
                      {egress.inet4_bind_address && (
                        <p className="text-xs font-mono text-slate-400">
                          <span className="text-slate-500">IPv4:</span> {egress.inet4_bind_address}
                        </p>
                      )}
                      {egress.inet6_bind_address && (
                        <p className="text-xs font-mono text-slate-400">
                          <span className="text-slate-500">IPv6:</span> {egress.inet6_bind_address}
                        </p>
                      )}
                    </div>

                    <div className="mt-3">
                      <button
                        onClick={() => handleSpeedTest(egress.tag)}
                        disabled={speedTestStatus[egress.tag]?.loading}
                        className={`w-full flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                          speedTestStatus[egress.tag]?.result
                            ? speedTestStatus[egress.tag].result?.success
                              ? "bg-emerald-500/20 text-emerald-400"
                              : "bg-red-500/20 text-red-400"
                            : "bg-slate-800/50 text-slate-300 hover:bg-slate-700"
                        }`}
                      >
                        {speedTestStatus[egress.tag]?.loading ? (
                          <>
                            <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                            {t('egress.speedTesting')}
                          </>
                        ) : speedTestStatus[egress.tag]?.result ? (
                          <>
                            {speedTestStatus[egress.tag].result?.success ? (
                              <CheckCircleIcon className="h-3.5 w-3.5" />
                            ) : (
                              <XCircleIcon className="h-3.5 w-3.5" />
                            )}
                            {speedTestStatus[egress.tag].result?.message}
                          </>
                        ) : (
                          <>
                            <ChartBarIcon className="h-3.5 w-3.5" />
                            {t('egress.speedTest')}
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* OpenVPN Egress */}
          {filteredOpenvpn.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
                  <LockClosedIcon className="h-4 w-4" />
                  {t('openvpnEgress.title')} ({filteredOpenvpn.length})
                </h3>
                {activeTab === "openvpn" && (
                  <button
                    onClick={handleAddOpenvpnEgress}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-orange-500/20 hover:bg-orange-500/30 text-orange-400 text-xs font-medium transition-colors"
                  >
                    <PlusIcon className="h-3.5 w-3.5" />
                    {t('openvpnEgress.addEgress')}
                  </button>
                )}
              </div>
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                {filteredOpenvpn.map((egress) => (
                  <div
                    key={egress.tag}
                    className={`rounded-xl border p-4 ${egress.enabled ? "bg-orange-500/5 border-orange-500/20" : "bg-white/5 border-white/10 opacity-50"}`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${egress.enabled ? "bg-orange-500/20" : "bg-white/10"}`}>
                          <LockClosedIcon className={`h-5 w-5 ${egress.enabled ? "text-orange-400" : "text-slate-400"}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-semibold text-white">{egress.tag}</h4>
                            {egress.enabled ? (
                              <CheckCircleIcon className="h-4 w-4 text-orange-400" />
                            ) : (
                              <XCircleIcon className="h-4 w-4 text-slate-500" />
                            )}
                          </div>
                          <p className="text-xs text-slate-500">{egress.description || t('openvpnEgress.defaultDescription')}</p>
                        </div>
                      </div>
                      <div className="flex gap-1 flex-shrink-0">
                        <button
                          onClick={() => handleEditOpenvpnEgress(egress)}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-white/10 hover:text-white"
                          title={t('common.edit')}
                        >
                          <PencilIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteOpenvpnEgress(egress.tag)}
                          disabled={actionLoading === `delete-openvpn-${egress.tag}`}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                          title={t('common.delete')}
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>

                    <div className="mt-3 pt-3 border-t border-white/5 space-y-1">
                      <p className="text-xs text-slate-400">
                        <span className="text-slate-500">{t('openvpnEgress.remoteHost')}:</span> {egress.remote_host}:{egress.remote_port}
                      </p>
                      <p className="text-xs text-slate-400">
                        <span className="text-slate-500">{t('openvpnEgress.protocol')}:</span> {egress.protocol.toUpperCase()}
                      </p>
                      {egress.socks_port && (
                        <p className="text-xs font-mono text-slate-400">
                          <span className="text-slate-500">{t('openvpnEgress.socksPort')}:</span> {egress.socks_port}
                        </p>
                      )}
                    </div>

                    <div className="mt-3">
                      <button
                        onClick={() => handleSpeedTest(egress.tag)}
                        disabled={speedTestStatus[egress.tag]?.loading}
                        className={`w-full flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                          speedTestStatus[egress.tag]?.result
                            ? speedTestStatus[egress.tag].result?.success
                              ? "bg-emerald-500/20 text-emerald-400"
                              : "bg-red-500/20 text-red-400"
                            : "bg-slate-800/50 text-slate-300 hover:bg-slate-700"
                        }`}
                      >
                        {speedTestStatus[egress.tag]?.loading ? (
                          <>
                            <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                            {t('egress.speedTesting')}
                          </>
                        ) : speedTestStatus[egress.tag]?.result ? (
                          <>
                            {speedTestStatus[egress.tag].result?.success ? (
                              <CheckCircleIcon className="h-3.5 w-3.5" />
                            ) : (
                              <XCircleIcon className="h-3.5 w-3.5" />
                            )}
                            {speedTestStatus[egress.tag].result?.message}
                          </>
                        ) : (
                          <>
                            <ChartBarIcon className="h-3.5 w-3.5" />
                            {t('egress.speedTest')}
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* V2Ray Egress */}
          {filteredV2ray.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
                  <ServerIcon className="h-4 w-4" />
                  V2Ray ({filteredV2ray.length})
                </h3>
                {activeTab === "v2ray" && (
                  <button
                    onClick={handleAddV2rayEgress}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-violet-500/20 hover:bg-violet-500/30 text-violet-400 text-xs font-medium transition-colors"
                  >
                    <PlusIcon className="h-3.5 w-3.5" />
                    {t('v2rayEgress.addEgress')}
                  </button>
                )}
              </div>
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                {filteredV2ray.map((egress) => (
                  <div
                    key={egress.tag}
                    className={`rounded-xl border p-4 ${egress.enabled ? "bg-violet-500/5 border-violet-500/20" : "bg-white/5 border-white/10 opacity-50"}`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${egress.enabled ? "bg-violet-500/20" : "bg-white/10"}`}>
                          <ServerIcon className={`h-5 w-5 ${egress.enabled ? "text-violet-400" : "text-slate-400"}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-semibold text-white">{egress.tag}</h4>
                            {egress.enabled ? (
                              <CheckCircleIcon className="h-4 w-4 text-violet-400" />
                            ) : (
                              <XCircleIcon className="h-4 w-4 text-slate-500" />
                            )}
                          </div>
                          <p className="text-xs text-slate-500">{egress.description || t('v2rayEgress.defaultDescription')}</p>
                        </div>
                      </div>
                      <div className="flex gap-1 flex-shrink-0">
                        <button
                          onClick={() => handleEditV2rayEgress(egress)}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-white/10 hover:text-white"
                          title={t('common.edit')}
                        >
                          <PencilIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteV2rayEgress(egress.tag)}
                          disabled={actionLoading === `delete-v2ray-${egress.tag}`}
                          className="p-1.5 rounded-lg text-slate-400 hover:bg-red-500/20 hover:text-red-400"
                          title={t('common.delete')}
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>

                    <div className="mt-3 pt-3 border-t border-white/5 space-y-1">
                      <p className="text-xs text-slate-400">
                        <span className="text-slate-500">{t('v2rayEgress.protocol')}:</span> {getV2rayProtocolLabel(egress.protocol)}
                      </p>
                      <p className="text-xs text-slate-400">
                        <span className="text-slate-500">{t('v2rayEgress.server')}:</span> {egress.server}:{egress.server_port}
                      </p>
                      <p className="text-xs text-slate-400">
                        <span className="text-slate-500">{t('v2rayEgress.transport')}:</span> {getV2rayTransportLabel(egress.transport_type)}
                        {egress.tls_enabled === 1 && " + TLS"}
                      </p>
                    </div>

                    <div className="mt-3">
                      <button
                        onClick={() => handleSpeedTest(egress.tag)}
                        disabled={speedTestStatus[egress.tag]?.loading}
                        className={`w-full flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                          speedTestStatus[egress.tag]?.result
                            ? speedTestStatus[egress.tag].result?.success
                              ? "bg-emerald-500/20 text-emerald-400"
                              : "bg-red-500/20 text-red-400"
                            : "bg-slate-800/50 text-slate-300 hover:bg-slate-700"
                        }`}
                      >
                        {speedTestStatus[egress.tag]?.loading ? (
                          <>
                            <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                            {t('egress.speedTesting')}
                          </>
                        ) : speedTestStatus[egress.tag]?.result ? (
                          <>
                            {speedTestStatus[egress.tag].result?.success ? (
                              <CheckCircleIcon className="h-3.5 w-3.5" />
                            ) : (
                              <XCircleIcon className="h-3.5 w-3.5" />
                            )}
                            {speedTestStatus[egress.tag].result?.message}
                          </>
                        ) : (
                          <>
                            <ChartBarIcon className="h-3.5 w-3.5" />
                            {t('egress.speedTest')}
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}

      {/* PIA Modal */}
      {showPiaModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
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
                  {t('common.description')}
                </label>
                <input
                  type="text"
                  value={piaFormDescription}
                  onChange={(e) => setPiaFormDescription(e.target.value)}
                  placeholder={piaFormTag || t('egress.descriptionPlaceholder')}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
                <p className="text-xs text-slate-500 mt-1">{t('egress.descriptionHint')}</p>
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
                  (piaModalMode === "add" && (!piaFormTag || !piaFormRegionId)) ||
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
        </div>,
        document.body
      )}

      {/* Add Custom Modal */}
      {showAddModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-2xl">
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
        </div>,
        document.body
      )}

      {/* Edit Custom Modal */}
      {showEditModal && editingEgress && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-2xl">
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
        </div>,
        document.body
      )}

      {/* Direct Egress Modal */}
      {showDirectModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-lg">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">
                  {directModalMode === "add" ? t('directEgress.addDirectEgress') : t('directEgress.editTitle', { tag: editingDirectEgress?.tag })}
                </h2>
                <button
                  onClick={() => {
                    setShowDirectModal(false);
                    resetDirectForm();
                  }}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              {directModalMode === "add" && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t('directEgress.tag')} <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    value={directFormTag}
                    onChange={(e) => setDirectFormTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-"))}
                    placeholder={t('directEgress.tagPlaceholder')}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                  />
                  <p className="text-xs text-slate-500 mt-1">{t('directEgress.tagHint')}</p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t('common.description')}
                </label>
                <input
                  type="text"
                  value={directFormDescription}
                  onChange={(e) => setDirectFormDescription(e.target.value)}
                  placeholder={t('directEgress.descriptionPlaceholder')}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                />
              </div>

              <div className="rounded-lg bg-cyan-500/10 border border-cyan-500/20 p-3 mb-4">
                <p className="text-xs text-cyan-300">{t('directEgress.bindHint')}</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t('directEgress.bindInterface')}
                </label>
                <input
                  type="text"
                  value={directFormBindInterface}
                  onChange={(e) => setDirectFormBindInterface(e.target.value)}
                  placeholder={t('directEgress.bindInterfacePlaceholder')}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t('directEgress.inet4BindAddress')}
                </label>
                <input
                  type="text"
                  value={directFormInet4Address}
                  onChange={(e) => setDirectFormInet4Address(e.target.value)}
                  placeholder={t('directEgress.inet4Placeholder')}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  {t('directEgress.inet6BindAddress')}
                </label>
                <input
                  type="text"
                  value={directFormInet6Address}
                  onChange={(e) => setDirectFormInet6Address(e.target.value)}
                  placeholder={t('directEgress.inet6Placeholder')}
                  className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono"
                />
              </div>
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowDirectModal(false);
                  resetDirectForm();
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={directModalMode === "add" ? handleCreateDirectEgress : handleUpdateDirectEgress}
                disabled={
                  (directModalMode === "add" ? actionLoading === "create-direct" : actionLoading === "update-direct") ||
                  (directModalMode === "add" && !directFormTag) ||
                  (!directFormBindInterface && !directFormInet4Address && !directFormInet6Address)
                }
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {(actionLoading === "create-direct" || actionLoading === "update-direct") ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : directModalMode === "add" ? (
                  <PlusIcon className="h-4 w-4" />
                ) : (
                  <CheckIcon className="h-4 w-4" />
                )}
                {directModalMode === "add" ? t('common.add') : t('common.save')}
              </button>
            </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Direct Default DNS Modal */}
      {showDirectDefaultModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-md">
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-bold text-white">{t('directDefault.editTitle')}</h2>
                  <button
                    onClick={() => setShowDirectDefaultModal(false)}
                    className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>

              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">
                    {t('directDefault.dnsServers')} <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    value={directDefaultFormDns}
                    onChange={(e) => setDirectDefaultFormDns(e.target.value)}
                    placeholder={t('directDefault.dnsPlaceholder')}
                    className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono"
                  />
                  <p className="text-xs text-slate-500 mt-1">{t('directDefault.dnsHint')}</p>
                </div>

                <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-3">
                  <p className="text-xs text-emerald-300">{t('directDefault.dnsNote')}</p>
                </div>
              </div>

              <div className="p-6 border-t border-white/10 flex justify-end gap-3">
                <button
                  onClick={() => setShowDirectDefaultModal(false)}
                  className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
                >
                  {t('common.cancel')}
                </button>
                <button
                  onClick={handleSaveDirectDefault}
                  disabled={actionLoading === "save-direct-default" || !(directDefaultFormDns || "").trim()}
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  {actionLoading === "save-direct-default" ? (
                    <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                  ) : (
                    <CheckIcon className="h-4 w-4" />
                  )}
                  {t('common.save')}
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* OpenVPN Modal */}
      {showOpenvpnModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-2xl">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">
                  {openvpnModalMode === "add" ? t('openvpnEgress.addOpenvpnEgress') : t('openvpnEgress.editTitle')}
                </h2>
                <button
                  onClick={() => {
                    setShowOpenvpnModal(false);
                    resetOpenvpnForm();
                  }}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
              {/* Import Method (only for add mode) */}
              {openvpnModalMode === "add" && (
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.importOvpn')}</label>
                  <div className="flex gap-2">
                    {["upload", "paste", "manual"].map((method) => (
                      <button
                        key={method}
                        onClick={() => setOpenvpnImportMethod(method as OpenVPNImportMethod)}
                        className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                          openvpnImportMethod === method
                            ? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
                            : "bg-white/5 text-slate-400 border border-white/10 hover:bg-white/10"
                        }`}
                      >
                        {method === "upload" ? t('openvpnEgress.uploadOvpn') : method === "paste" ? t('openvpnEgress.pasteOvpn') : t('customEgress.manualInput')}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Upload .ovpn file */}
              {openvpnModalMode === "add" && openvpnImportMethod === "upload" && (
                <div>
                  <input
                    type="file"
                    ref={openvpnFileInputRef}
                    accept=".ovpn,.conf"
                    onChange={handleOpenvpnFileUpload}
                    className="hidden"
                  />
                  <button
                    onClick={() => openvpnFileInputRef.current?.click()}
                    className="w-full p-8 rounded-xl border-2 border-dashed border-white/20 hover:border-orange-500/50 transition-colors flex flex-col items-center gap-2"
                  >
                    <ArrowUpTrayIcon className="h-8 w-8 text-slate-400" />
                    <span className="text-slate-400">{t('openvpnEgress.clickToUpload')}</span>
                    <span className="text-xs text-slate-500">{t('openvpnEgress.uploadHint')}</span>
                  </button>
                  {openvpnParsedConfig && (
                    <div className="mt-2 p-2 rounded bg-emerald-500/10 text-emerald-400 text-sm flex items-center gap-2">
                      <CheckIcon className="h-4 w-4" />
                      {t('openvpnEgress.parseSuccess')}
                    </div>
                  )}
                </div>
              )}

              {/* Paste config */}
              {openvpnModalMode === "add" && openvpnImportMethod === "paste" && (
                <div className="space-y-3">
                  <textarea
                    value={openvpnPasteContent}
                    onChange={(e) => setOpenvpnPasteContent(e.target.value)}
                    placeholder={t('openvpnEgress.pastePlaceholder')}
                    className="w-full h-40 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-sm"
                  />
                  <button
                    onClick={() => parseOpenvpnConfig(openvpnPasteContent)}
                    disabled={!(openvpnPasteContent || "").trim()}
                    className="px-4 py-2 rounded-lg bg-orange-500/20 text-orange-400 text-sm font-medium disabled:opacity-50"
                  >
                    {t('openvpnEgress.parseConfig')}
                  </button>
                  {openvpnParseError && (
                    <div className="p-2 rounded bg-red-500/10 text-red-400 text-sm">{openvpnParseError}</div>
                  )}
                </div>
              )}

              {/* Form fields */}
              {(openvpnImportMethod === "manual" || openvpnParsedConfig || openvpnModalMode === "edit") && (
                <div className="space-y-4">
                  {/* Tag (only for add mode) */}
                  {openvpnModalMode === "add" && (
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('openvpnEgress.tag')} <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="text"
                        value={openvpnFormTag}
                        onChange={(e) => setOpenvpnFormTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-"))}
                        placeholder={t('openvpnEgress.tagPlaceholder')}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                      />
                      <p className="text-xs text-slate-500 mt-1">{t('openvpnEgress.tagHint')}</p>
                    </div>
                  )}

                  {/* Description */}
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">{t('common.description')}</label>
                    <input
                      type="text"
                      value={openvpnFormDescription}
                      onChange={(e) => setOpenvpnFormDescription(e.target.value)}
                      placeholder={t('openvpnEgress.descriptionPlaceholder')}
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                    />
                  </div>

                  {/* Server info row */}
                  <div className="grid grid-cols-4 gap-3">
                    <div className="col-span-2">
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('openvpnEgress.remoteHost')} <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="text"
                        value={openvpnFormRemoteHost}
                        onChange={(e) => setOpenvpnFormRemoteHost(e.target.value)}
                        placeholder={t('openvpnEgress.remoteHostPlaceholder')}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.remotePort')}</label>
                      <input
                        type="number"
                        value={openvpnFormRemotePort}
                        onChange={(e) => setOpenvpnFormRemotePort(parseInt(e.target.value) || 1194)}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.protocol')}</label>
                      <select
                        value={openvpnFormProtocol}
                        onChange={(e) => setOpenvpnFormProtocol(e.target.value as "udp" | "tcp")}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand"
                      >
                        <option value="udp">{t('openvpnEgress.udp')}</option>
                        <option value="tcp">{t('openvpnEgress.tcp')}</option>
                      </select>
                    </div>
                  </div>

                  {/* CA Certificate */}
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">
                      {t('openvpnEgress.caCert')} <span className="text-red-400">*</span>
                    </label>
                    <textarea
                      value={openvpnFormCaCert}
                      onChange={(e) => setOpenvpnFormCaCert(e.target.value)}
                      placeholder={t('openvpnEgress.caCertPlaceholder')}
                      className="w-full h-24 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-xs"
                    />
                    <p className="text-xs text-slate-500 mt-1">{t('openvpnEgress.caCertHint')}</p>
                  </div>

                  {/* Client Certificate & Key row */}
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.clientCert')}</label>
                      <textarea
                        value={openvpnFormClientCert}
                        onChange={(e) => setOpenvpnFormClientCert(e.target.value)}
                        placeholder={t('openvpnEgress.clientCertPlaceholder')}
                        className="w-full h-20 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.clientKey')}</label>
                      <textarea
                        value={openvpnFormClientKey}
                        onChange={(e) => setOpenvpnFormClientKey(e.target.value)}
                        placeholder={t('openvpnEgress.clientKeyPlaceholder')}
                        className="w-full h-20 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-xs"
                      />
                    </div>
                  </div>

                  {/* TLS Auth/Crypt row */}
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.tlsAuth')}</label>
                      <textarea
                        value={openvpnFormTlsAuth}
                        onChange={(e) => setOpenvpnFormTlsAuth(e.target.value)}
                        placeholder={t('openvpnEgress.tlsAuthPlaceholder')}
                        className="w-full h-20 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.tlsCrypt')}</label>
                      <textarea
                        value={openvpnFormTlsCrypt}
                        onChange={(e) => setOpenvpnFormTlsCrypt(e.target.value)}
                        placeholder={t('openvpnEgress.tlsCryptPlaceholder')}
                        className="w-full h-20 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-xs"
                      />
                    </div>
                  </div>

                  {/* CRL Verify */}
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.crlVerify')}</label>
                    <textarea
                      value={openvpnFormCrlVerify}
                      onChange={(e) => setOpenvpnFormCrlVerify(e.target.value)}
                      placeholder={t('openvpnEgress.crlVerifyPlaceholder')}
                      className="w-full h-20 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-xs"
                    />
                  </div>

                  {/* Auth Required Hint / Validation Error */}
                  <div ref={authFieldsRef}>
                    {(showAuthRequiredHint || authValidationError) && (
                      <div className={`p-3 rounded-lg text-sm flex items-center gap-2 ${
                        authValidationError
                          ? 'bg-red-500/20 border-2 border-red-500 text-red-400 animate-pulse'
                          : 'bg-orange-500/10 border border-orange-500/30 text-orange-400'
                      }`}>
                        <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <span className="font-medium">
                          {authValidationError
                            ? t('openvpnEgress.authValidationError')
                            : t('openvpnEgress.authRequiredHint')
                          }
                        </span>
                      </div>
                    )}

                    {/* Auth User/Pass row */}
                    <div className={`grid grid-cols-2 gap-3 ${(showAuthRequiredHint || authValidationError) ? 'mt-3' : ''}`}>
                      <div>
                        <label className={`block text-sm font-medium mb-2 ${authValidationError ? 'text-red-400' : showAuthRequiredHint ? 'text-orange-400' : 'text-slate-400'}`}>
                          {t('openvpnEgress.authUser')} {(showAuthRequiredHint || authValidationError) && <span className={authValidationError ? 'text-red-400' : 'text-orange-400'}>*</span>}
                        </label>
                        <input
                          type="text"
                          value={openvpnFormAuthUser}
                          onChange={(e) => {
                            setOpenvpnFormAuthUser(e.target.value);
                            if (authValidationError) setAuthValidationError(false);
                          }}
                          placeholder={t('openvpnEgress.authUserPlaceholder')}
                          className={`w-full px-3 py-2 rounded-lg bg-white/5 border text-white placeholder-slate-500 focus:outline-none focus:border-brand ${
                            authValidationError ? 'border-red-500 border-2' : showAuthRequiredHint ? 'border-orange-500/50' : 'border-white/10'
                          }`}
                        />
                      </div>
                      <div>
                        <label className={`block text-sm font-medium mb-2 ${authValidationError ? 'text-red-400' : showAuthRequiredHint ? 'text-orange-400' : 'text-slate-400'}`}>
                          {t('openvpnEgress.authPass')} {(showAuthRequiredHint || authValidationError) && <span className={authValidationError ? 'text-red-400' : 'text-orange-400'}>*</span>}
                        </label>
                        <input
                          type="password"
                          value={openvpnFormAuthPass}
                          onChange={(e) => {
                            setOpenvpnFormAuthPass(e.target.value);
                            if (authValidationError) setAuthValidationError(false);
                          }}
                          placeholder={openvpnModalMode === "edit" ? t('openvpnEgress.authPassKeepExisting') : t('openvpnEgress.authPassPlaceholder')}
                          className={`w-full px-3 py-2 rounded-lg bg-white/5 border text-white placeholder-slate-500 focus:outline-none focus:border-brand ${
                            authValidationError ? 'border-red-500 border-2' : showAuthRequiredHint ? 'border-orange-500/50' : 'border-white/10'
                          }`}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Cipher/Auth/Compress row */}
                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.cipher')}</label>
                      <select
                        value={openvpnFormCipher}
                        onChange={(e) => setOpenvpnFormCipher(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-brand cursor-pointer"
                      >
                        <option value="AES-256-GCM" className="bg-slate-800 text-white">AES-256-GCM</option>
                        <option value="AES-128-GCM" className="bg-slate-800 text-white">AES-128-GCM</option>
                        <option value="AES-256-CBC" className="bg-slate-800 text-white">AES-256-CBC</option>
                        <option value="AES-128-CBC" className="bg-slate-800 text-white">AES-128-CBC</option>
                        <option value="CHACHA20-POLY1305" className="bg-slate-800 text-white">CHACHA20-POLY1305</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.auth')}</label>
                      <select
                        value={openvpnFormAuth}
                        onChange={(e) => setOpenvpnFormAuth(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-brand cursor-pointer"
                      >
                        <option value="SHA256" className="bg-slate-800 text-white">SHA256</option>
                        <option value="SHA512" className="bg-slate-800 text-white">SHA512</option>
                        <option value="SHA1" className="bg-slate-800 text-white">SHA1</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.compress')}</label>
                      <select
                        value={openvpnFormCompress}
                        onChange={(e) => setOpenvpnFormCompress(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-white/10 text-white focus:outline-none focus:border-brand cursor-pointer"
                      >
                        <option value="" className="bg-slate-800 text-white">{t('openvpnEgress.compressNone')}</option>
                        <option value="stub" className="bg-slate-800 text-white">{t('openvpnEgress.compressAdaptive')}</option>
                        <option value="lzo" className="bg-slate-800 text-white">LZO</option>
                        <option value="lz4" className="bg-slate-800 text-white">LZ4</option>
                        <option value="lz4-v2" className="bg-slate-800 text-white">LZ4-V2</option>
                      </select>
                    </div>
                  </div>

                  {/* Extra Options */}
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">{t('openvpnEgress.extraOptions')}</label>
                    <textarea
                      value={openvpnFormExtraOptions}
                      onChange={(e) => setOpenvpnFormExtraOptions(e.target.value)}
                      placeholder={t('openvpnEgress.extraOptionsPlaceholder')}
                      className="w-full h-16 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-brand font-mono text-xs"
                    />
                    <p className="text-xs text-slate-500 mt-1">{t('openvpnEgress.extraOptionsHint')}</p>
                  </div>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowOpenvpnModal(false);
                  resetOpenvpnForm();
                }}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-sm transition-colors"
              >
                {t('common.cancel')}
              </button>
              {/* Force save button - only show when auth validation error */}
              {authValidationError && openvpnModalMode === "add" && (
                <button
                  onClick={() => handleCreateOpenvpnEgress(true)}
                  disabled={actionLoading === "create-openvpn"}
                  className="px-4 py-2 rounded-lg bg-slate-600 hover:bg-slate-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  {actionLoading === "create-openvpn" ? (
                    <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                  ) : (
                    <ExclamationTriangleIcon className="h-4 w-4" />
                  )}
                  {t('openvpnEgress.forceSave')}
                </button>
              )}
              <button
                onClick={() => openvpnModalMode === "add" ? handleCreateOpenvpnEgress() : handleUpdateOpenvpnEgress()}
                disabled={
                  (openvpnModalMode === "add" ? actionLoading === "create-openvpn" : actionLoading === "update-openvpn") ||
                  (openvpnModalMode === "add" && !openvpnFormTag) ||
                  !openvpnFormRemoteHost ||
                  !openvpnFormCaCert
                }
                className="px-4 py-2 rounded-lg bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {(actionLoading === "create-openvpn" || actionLoading === "update-openvpn") ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : openvpnModalMode === "add" ? (
                  <PlusIcon className="h-4 w-4" />
                ) : (
                  <CheckIcon className="h-4 w-4" />
                )}
                {openvpnModalMode === "add" ? t('common.add') : t('common.save')}
              </button>
            </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* V2Ray Modal */}
      {showV2rayModal && createPortal(
        <div className="fixed inset-0 bg-black/50 z-50 overflow-y-auto">
          <div className="min-h-screen flex items-center justify-center p-4">
            <div className="bg-slate-900 rounded-2xl border border-white/10 w-full max-w-2xl">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">
                  {v2rayModalMode === "add" ? t('v2rayEgress.addV2rayEgress') : t('v2rayEgress.editV2rayEgress', { tag: editingV2rayEgress?.tag })}
                </h2>
                <button
                  onClick={() => {
                    setShowV2rayModal(false);
                    resetV2rayForm();
                  }}
                  className="p-1 rounded-lg hover:bg-white/10 text-slate-400"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 max-h-[70vh] overflow-y-auto space-y-6">
              {/* Import Method Tabs (only for add mode) */}
              {v2rayModalMode === "add" && (
                <div className="flex gap-2 mb-4">
                  <button
                    onClick={() => setV2rayImportMethod("uri")}
                    className={`px-4 py-2 text-sm rounded-lg transition-colors ${
                      v2rayImportMethod === "uri"
                        ? "bg-violet-500 text-white"
                        : "bg-white/5 text-slate-400 hover:text-white"
                    }`}
                  >
                    {t('v2rayEgress.importUri')}
                  </button>
                  <button
                    onClick={() => setV2rayImportMethod("manual")}
                    className={`px-4 py-2 text-sm rounded-lg transition-colors ${
                      v2rayImportMethod === "manual"
                        ? "bg-violet-500 text-white"
                        : "bg-white/5 text-slate-400 hover:text-white"
                    }`}
                  >
                    {t('v2rayEgress.manualConfig')}
                  </button>
                </div>
              )}

              {/* URI Import */}
              {v2rayModalMode === "add" && v2rayImportMethod === "uri" && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">
                      {t('v2rayEgress.pasteUri')}
                    </label>
                    <textarea
                      value={v2rayUriInput}
                      onChange={(e) => setV2rayUriInput(e.target.value)}
                      placeholder="vmess://... 或 vless://... 或 trojan://..."
                      className="w-full h-32 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500 font-mono text-sm resize-none"
                    />
                  </div>
                  {v2rayParseError && (
                    <div className="flex items-center gap-2 text-red-400 text-sm">
                      <ExclamationTriangleIcon className="h-4 w-4" />
                      {v2rayParseError}
                    </div>
                  )}
                  <button
                    onClick={() => parseV2rayUri(v2rayUriInput)}
                    disabled={!(v2rayUriInput || "").trim()}
                    className="px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-600 text-white text-sm font-medium disabled:opacity-50"
                  >
                    {t('v2rayEgress.parseUri')}
                  </button>
                </div>
              )}

              {/* Manual Configuration */}
              {(v2rayModalMode === "edit" || v2rayImportMethod === "manual") && (
                <div className="space-y-4">
                  {/* Basic Info */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('v2rayEgress.tag')} <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="text"
                        value={v2rayFormTag}
                        onChange={(e) => setV2rayFormTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-"))}
                        placeholder={t('v2rayEgress.tagPlaceholder')}
                        disabled={v2rayModalMode === "edit"}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500 disabled:opacity-50"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('common.description')}
                      </label>
                      <input
                        type="text"
                        value={v2rayFormDescription}
                        onChange={(e) => setV2rayFormDescription(e.target.value)}
                        placeholder={t('v2rayEgress.descriptionPlaceholder')}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                      />
                    </div>
                  </div>

                  {/* Protocol Selection */}
                  <div>
                    <label className="block text-sm font-medium text-slate-400 mb-2">
                      {t('v2rayEgress.protocol')} <span className="text-red-400">*</span>
                    </label>
                    <div className="flex gap-2">
                      {V2RAY_PROTOCOLS.map((p) => (
                        <button
                          key={p.value}
                          onClick={() => setV2rayFormProtocol(p.value)}
                          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                            v2rayFormProtocol === p.value
                              ? "bg-violet-500 text-white"
                              : "bg-white/5 text-slate-400 hover:text-white hover:bg-white/10"
                          }`}
                        >
                          {p.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Server Settings */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('v2rayEgress.server')} <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="text"
                        value={v2rayFormServer}
                        onChange={(e) => setV2rayFormServer(e.target.value)}
                        placeholder="example.com"
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('v2rayEgress.port')}
                      </label>
                      <input
                        type="number"
                        value={v2rayFormPort}
                        onChange={(e) => setV2rayFormPort(parseInt(e.target.value) || 443)}
                        min={1}
                        max={65535}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                      />
                    </div>
                  </div>

                  {/* Authentication (based on protocol) */}
                  {(v2rayFormProtocol === "vmess" || v2rayFormProtocol === "vless") && (
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        UUID <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="text"
                        value={v2rayFormUuid}
                        onChange={(e) => setV2rayFormUuid(e.target.value)}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500 font-mono text-sm"
                      />
                    </div>
                  )}

                  {v2rayFormProtocol === "trojan" && (
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        {t('v2rayEgress.password')} <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="password"
                        value={v2rayFormPassword}
                        onChange={(e) => setV2rayFormPassword(e.target.value)}
                        placeholder={v2rayModalMode === "edit" ? t('v2rayEgress.passwordPlaceholder') : ""}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                      />
                    </div>
                  )}

                  {/* VMess specific options */}
                  {v2rayFormProtocol === "vmess" && (
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">
                          {t('v2rayEgress.security')}
                        </label>
                        <select
                          value={v2rayFormSecurity}
                          onChange={(e) => setV2rayFormSecurity(e.target.value)}
                          className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-violet-500"
                        >
                          {V2RAY_SECURITY_OPTIONS.map((opt) => (
                            <option key={opt.value} value={opt.value}>{opt.label}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">
                          Alter ID
                        </label>
                        <input
                          type="number"
                          value={v2rayFormAlterId}
                          onChange={(e) => setV2rayFormAlterId(parseInt(e.target.value) || 0)}
                          min={0}
                          className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                        />
                      </div>
                    </div>
                  )}

                  {/* VLESS specific options */}
                  {v2rayFormProtocol === "vless" && (
                    <div>
                      <label className="block text-sm font-medium text-slate-400 mb-2">
                        Flow ({t('v2rayEgress.optional')})
                      </label>
                      <select
                        value={v2rayFormFlow}
                        onChange={(e) => setV2rayFormFlow(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-violet-500"
                      >
                        {VLESS_FLOW_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>{opt.label}</option>
                        ))}
                      </select>
                      <p className="text-xs text-slate-500 mt-1">{t('v2rayEgress.flowHint')}</p>
                    </div>
                  )}

                  {/* TLS Settings (hidden when REALITY is enabled) */}
                  {!v2rayFormRealityEnabled && (
                  <div className="border-t border-white/10 pt-4">
                    <div className="flex items-center gap-3 mb-4">
                      <input
                        type="checkbox"
                        id="v2ray-tls-enabled"
                        checked={v2rayFormTlsEnabled}
                        onChange={(e) => setV2rayFormTlsEnabled(e.target.checked)}
                        className="w-4 h-4 rounded border-white/20 bg-white/5 text-violet-500 focus:ring-violet-500"
                      />
                      <label htmlFor="v2ray-tls-enabled" className="text-sm font-medium text-white">
                        {t('v2rayEgress.enableTls')}
                      </label>
                    </div>

                    {v2rayFormTlsEnabled && (
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-slate-400 mb-2">
                            SNI ({t('v2rayEgress.optional')})
                          </label>
                          <input
                            type="text"
                            value={v2rayFormTlsSni}
                            onChange={(e) => setV2rayFormTlsSni(e.target.value)}
                            placeholder={v2rayFormServer || "example.com"}
                            className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-slate-400 mb-2">
                            {t('v2rayEgress.fingerprint')}
                          </label>
                          <select
                            value={v2rayFormTlsFingerprint}
                            onChange={(e) => setV2rayFormTlsFingerprint(e.target.value)}
                            className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-violet-500"
                          >
                            {V2RAY_TLS_FINGERPRINTS.map((opt) => (
                              <option key={opt.value} value={opt.value}>{opt.label}</option>
                            ))}
                          </select>
                        </div>
                        <div className="col-span-2 flex items-center gap-3">
                          <input
                            type="checkbox"
                            id="v2ray-tls-insecure"
                            checked={v2rayFormTlsAllowInsecure}
                            onChange={(e) => setV2rayFormTlsAllowInsecure(e.target.checked)}
                            className="w-4 h-4 rounded border-white/20 bg-white/5 text-violet-500 focus:ring-violet-500"
                          />
                          <label htmlFor="v2ray-tls-insecure" className="text-sm text-slate-400">
                            {t('v2rayEgress.allowInsecure')}
                          </label>
                        </div>
                      </div>
                    )}
                  </div>
                  )}

                  {/* REALITY Settings (VLESS only) */}
                  {v2rayFormProtocol === "vless" && (
                    <div className="border-t border-white/10 pt-4">
                      <div className="flex items-center gap-3 mb-4">
                        <input
                          type="checkbox"
                          id="v2ray-reality-enabled"
                          checked={v2rayFormRealityEnabled}
                          onChange={(e) => {
                            setV2rayFormRealityEnabled(e.target.checked);
                            // REALITY replaces TLS
                            if (e.target.checked) {
                              setV2rayFormTlsEnabled(false);
                            }
                          }}
                          className="w-4 h-4 rounded border-white/20 bg-white/5 text-violet-500 focus:ring-violet-500"
                        />
                        <label htmlFor="v2ray-reality-enabled" className="text-sm font-medium text-white">
                          {t('v2rayEgress.enableReality')}
                        </label>
                        <span className="text-xs text-slate-500 ml-2">({t('v2rayEgress.realityHint')})</span>
                      </div>

                      {v2rayFormRealityEnabled && (
                        <div className="grid grid-cols-2 gap-4">
                          <div className="col-span-2">
                            <label className="block text-sm font-medium text-slate-400 mb-2">
                              {t('v2rayEgress.realityPublicKey')} <span className="text-red-400">*</span>
                            </label>
                            <input
                              type="text"
                              value={v2rayFormRealityPublicKey}
                              onChange={(e) => setV2rayFormRealityPublicKey(e.target.value)}
                              placeholder="Server public key (base64)"
                              className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500 font-mono text-sm"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-400 mb-2">
                              {t('v2rayEgress.realityShortId')}
                            </label>
                            <input
                              type="text"
                              value={v2rayFormRealityShortId}
                              onChange={(e) => setV2rayFormRealityShortId(e.target.value)}
                              placeholder="Short ID (hex)"
                              className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500 font-mono text-sm"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-400 mb-2">
                              SNI ({t('v2rayEgress.optional')})
                            </label>
                            <input
                              type="text"
                              value={v2rayFormTlsSni}
                              onChange={(e) => setV2rayFormTlsSni(e.target.value)}
                              placeholder="www.microsoft.com"
                              className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                            />
                          </div>
                          <div className="col-span-2">
                            <label className="block text-sm font-medium text-slate-400 mb-2">
                              {t('v2rayEgress.fingerprint')}
                            </label>
                            <select
                              value={v2rayFormTlsFingerprint}
                              onChange={(e) => setV2rayFormTlsFingerprint(e.target.value)}
                              className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white focus:outline-none focus:border-violet-500"
                            >
                              {V2RAY_TLS_FINGERPRINTS.map((opt) => (
                                <option key={opt.value} value={opt.value}>{opt.label}</option>
                              ))}
                            </select>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Transport Settings */}
                  <div className="border-t border-white/10 pt-4">
                    <label className="block text-sm font-medium text-slate-400 mb-2">
                      {t('v2rayEgress.transport')}
                    </label>
                    <div className="flex flex-wrap gap-2 mb-4">
                      {V2RAY_TRANSPORTS.map((t) => (
                        <button
                          key={t.value}
                          onClick={() => setV2rayFormTransportType(t.value)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                            v2rayFormTransportType === t.value
                              ? "bg-violet-500 text-white"
                              : "bg-white/5 text-slate-400 hover:text-white hover:bg-white/10"
                          }`}
                        >
                          {t.label}
                        </button>
                      ))}
                    </div>

                    {/* Transport-specific options */}
                    {(v2rayFormTransportType === "ws" || v2rayFormTransportType === "httpupgrade") && (
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-slate-400 mb-2">
                            Path
                          </label>
                          <input
                            type="text"
                            value={v2rayFormTransportPath}
                            onChange={(e) => setV2rayFormTransportPath(e.target.value)}
                            placeholder="/"
                            className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-slate-400 mb-2">
                            Host
                          </label>
                          <input
                            type="text"
                            value={v2rayFormTransportHost}
                            onChange={(e) => setV2rayFormTransportHost(e.target.value)}
                            placeholder={v2rayFormServer}
                            className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                          />
                        </div>
                      </div>
                    )}

                    {v2rayFormTransportType === "grpc" && (
                      <div>
                        <label className="block text-sm font-medium text-slate-400 mb-2">
                          Service Name
                        </label>
                        <input
                          type="text"
                          value={v2rayFormTransportServiceName}
                          onChange={(e) => setV2rayFormTransportServiceName(e.target.value)}
                          placeholder="grpc"
                          className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                        />
                      </div>
                    )}

                    {v2rayFormTransportType === "h2" && (
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-slate-400 mb-2">
                            Path
                          </label>
                          <input
                            type="text"
                            value={v2rayFormTransportPath}
                            onChange={(e) => setV2rayFormTransportPath(e.target.value)}
                            placeholder="/"
                            className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-slate-400 mb-2">
                            Host
                          </label>
                          <input
                            type="text"
                            value={v2rayFormTransportHost}
                            onChange={(e) => setV2rayFormTransportHost(e.target.value)}
                            placeholder={v2rayFormServer}
                            className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white placeholder-slate-500 focus:outline-none focus:border-violet-500"
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowV2rayModal(false);
                  resetV2rayForm();
                }}
                className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white text-sm transition-colors"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={() => v2rayModalMode === "add" ? handleCreateV2rayEgress() : handleUpdateV2rayEgress()}
                disabled={
                  (v2rayModalMode === "add" ? actionLoading === "create-v2ray" : actionLoading === "update-v2ray") ||
                  (v2rayModalMode === "add" && !v2rayFormTag) ||
                  !v2rayFormServer ||
                  ((v2rayFormProtocol === "vmess" || v2rayFormProtocol === "vless") && !v2rayFormUuid) ||
                  (v2rayFormProtocol === "trojan" && !v2rayFormPassword && v2rayModalMode === "add")
                }
                className="px-4 py-2 rounded-lg bg-violet-500 hover:bg-violet-600 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {(actionLoading === "create-v2ray" || actionLoading === "update-v2ray") ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : v2rayModalMode === "add" ? (
                  <PlusIcon className="h-4 w-4" />
                ) : (
                  <CheckIcon className="h-4 w-4" />
                )}
                {v2rayModalMode === "add" ? t('common.add') : t('common.save')}
              </button>
            </div>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}
