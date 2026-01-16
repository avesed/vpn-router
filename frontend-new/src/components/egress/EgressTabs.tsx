import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAllEgress, useDeleteCustomEgress, useDeleteDirectEgress, useDeleteWarpEgress, useDeleteOpenVPNEgress, useDeleteV2RayEgress, useEgressTraffic } from "../../api/hooks/useEgress";
import { useDeletePIALine, useReconnectPIALine, usePIAStatus } from "../../api/hooks/usePIA";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { EgressCard } from "./EgressCard";
import { Button } from "../ui/button";
import { Plus, Loader2, LogIn } from "lucide-react";
import { AddWireGuardDialog } from "./AddWireGuardDialog";
import { AddDirectDialog } from "./AddDirectDialog";
import { AddWarpDialog } from "./AddWarpDialog";
import { AddPIADialog, PIALoginDialog } from "./AddPIADialog";
import { AddOpenVPNDialog } from "./AddOpenVPNDialog";
import { AddV2RayDialog } from "./AddV2RayDialog";
import { toast } from "sonner";
import type { EgressItem, VpnProfile, OpenVPNEgress, V2RayEgress } from "../../types";

export function EgressTabs() {
  const { t } = useTranslation();
  const { data: allEgress, isLoading, error } = useAllEgress();
  const { data: trafficData } = useEgressTraffic(); // Auto-refresh every 10s
  const { data: piaStatus } = usePIAStatus();
  const deleteCustom = useDeleteCustomEgress();
  const deleteDirect = useDeleteDirectEgress();
  const deleteWarp = useDeleteWarpEgress();
  const deletePIA = useDeletePIALine();
  const reconnectPIA = useReconnectPIALine();
  const deleteOpenVPN = useDeleteOpenVPNEgress();
  const deleteV2Ray = useDeleteV2RayEgress();

  const [activeTab, setActiveTab] = useState("pia");
  const [showAddWireGuard, setShowAddWireGuard] = useState(false);
  const [showAddDirect, setShowAddDirect] = useState(false);
  const [showAddWarp, setShowAddWarp] = useState(false);
  const [showAddPIA, setShowAddPIA] = useState(false);
  const [showPIALogin, setShowPIALogin] = useState(false);
  const [editingPIA, setEditingPIA] = useState<VpnProfile | undefined>(undefined);
  const [showAddOpenVPN, setShowAddOpenVPN] = useState(false);
  const [editingOpenVPN, setEditingOpenVPN] = useState<OpenVPNEgress | undefined>(undefined);
  const [showAddV2Ray, setShowAddV2Ray] = useState(false);
  const [editingV2Ray, setEditingV2Ray] = useState<V2RayEgress | undefined>(undefined);
  const [pendingReconnectTag, setPendingReconnectTag] = useState<string | null>(null);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-2">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t("egress.loading")}</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <p className="text-destructive font-medium">{t("common.error")}</p>
          <p className="text-sm text-muted-foreground mt-1">{error.message}</p>
        </div>
      </div>
    );
  }

  if (!allEgress) return null;

  const handleDelete = (type: string, tag: string) => {
    if (!confirm(t("egress.deleteConfirm", { tag, defaultValue: `Are you sure you want to delete ${tag}?` }))) return;

    let promise;
    switch (type) {
      case "custom":
        promise = deleteCustom.mutateAsync(tag);
        break;
      case "direct":
        promise = deleteDirect.mutateAsync(tag);
        break;
      case "warp":
        promise = deleteWarp.mutateAsync(tag);
        break;
      case "pia":
        promise = deletePIA.mutateAsync(tag);
        break;
      case "openvpn":
        promise = deleteOpenVPN.mutateAsync(tag);
        break;
      case "v2ray":
        promise = deleteV2Ray.mutateAsync(tag);
        break;
      default:
        return;
    }

    toast.promise(promise, {
      loading: t("egress.deleting"),
      success: t("egress.deleteSuccess"),
      error: t("egress.deleteFailed"),
    });
  };

  const handleReconnectPIA = async (tag: string) => {
    // Check if PIA credentials are available
    if (!piaStatus?.has_credentials) {
      setPendingReconnectTag(tag);
      setShowPIALogin(true);
      return;
    }

    toast.promise(reconnectPIA.mutateAsync(tag), {
      loading: t("egress.pia.reconnecting", { defaultValue: "Reconnecting..." }),
      success: t("egress.pia.reconnectSuccess", { defaultValue: "Reconnect initiated" }),
      error: t("egress.pia.reconnectFailed", { defaultValue: "Reconnect failed" }),
    });
  };

  const handlePIALoginSuccess = () => {
    if (pendingReconnectTag) {
      handleReconnectPIA(pendingReconnectTag);
      setPendingReconnectTag(null);
    }
  };

  const renderEgressList = (list: EgressItem[], type: string) => {
    if (!list || list.length === 0) {
      return (
        <div className="text-center p-8 text-muted-foreground">
          {t("egress.noEgress", { type, defaultValue: `No ${type} egresses configured.` })}
        </div>
      );
    }
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {list.map((egress) => (
          <EgressCard
            key={egress.tag}
            egress={egress}
            onDelete={(tag) => handleDelete(type, tag)}
            onEdit={
              type === "pia" ? () => setEditingPIA(egress as unknown as VpnProfile) :
              type === "openvpn" ? () => setEditingOpenVPN(egress as unknown as OpenVPNEgress) :
              type === "v2ray" ? () => setEditingV2Ray(egress as unknown as V2RayEgress) :
              undefined
            }
            onReconnect={type === "pia" ? () => handleReconnectPIA(egress.tag) : undefined}
            showActions={true}
            trafficInfo={trafficData?.traffic?.[egress.tag]}
          />
        ))}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold tracking-tight">{t("egress.management")}</h2>
        <div className="flex gap-2">
          {activeTab === "pia" && (
            <>
              {!piaStatus?.has_credentials && (
                <Button variant="outline" onClick={() => setShowPIALogin(true)}>
                  <LogIn className="mr-2 h-4 w-4" /> {t("egress.pia.login", { defaultValue: "Login" })}
                </Button>
              )}
              <Button onClick={() => { setEditingPIA(undefined); setShowAddPIA(true); }}>
                <Plus className="mr-2 h-4 w-4" /> {t("egress.pia.addLine", { defaultValue: "Add PIA Line" })}
              </Button>
            </>
          )}
          {activeTab === "custom" && (
            <Button onClick={() => setShowAddWireGuard(true)}>
              <Plus className="mr-2 h-4 w-4" /> {t("egress.addWireGuard")}
            </Button>
          )}
          {activeTab === "direct" && (
            <Button onClick={() => setShowAddDirect(true)}>
              <Plus className="mr-2 h-4 w-4" /> {t("egress.addDirect")}
            </Button>
          )}
          {activeTab === "warp" && (
            <Button onClick={() => setShowAddWarp(true)}>
              <Plus className="mr-2 h-4 w-4" /> {t("egress.registerWarp")}
            </Button>
          )}
          {activeTab === "openvpn" && (
            <Button onClick={() => { setEditingOpenVPN(undefined); setShowAddOpenVPN(true); }}>
              <Plus className="mr-2 h-4 w-4" /> {t("egress.openvpn.add", { defaultValue: "Add OpenVPN" })}
            </Button>
          )}
          {activeTab === "v2ray" && (
            <Button onClick={() => { setEditingV2Ray(undefined); setShowAddV2Ray(true); }}>
              <Plus className="mr-2 h-4 w-4" /> {t("egress.v2ray.add", { defaultValue: "Add V2Ray" })}
            </Button>
          )}
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="pia">PIA</TabsTrigger>
          <TabsTrigger value="custom">WireGuard</TabsTrigger>
          <TabsTrigger value="direct">{t("common.direct")}</TabsTrigger>
          <TabsTrigger value="warp">WARP</TabsTrigger>
          <TabsTrigger value="openvpn">OpenVPN</TabsTrigger>
          <TabsTrigger value="v2ray">V2Ray</TabsTrigger>
        </TabsList>

        <TabsContent value="pia" className="mt-4">
          {renderEgressList(allEgress.pia, "pia")}
        </TabsContent>
        <TabsContent value="custom" className="mt-4">
          {renderEgressList(allEgress.custom, "custom")}
        </TabsContent>
        <TabsContent value="direct" className="mt-4">
          {renderEgressList(allEgress.direct, "direct")}
        </TabsContent>
        <TabsContent value="warp" className="mt-4">
          {renderEgressList(allEgress.warp || [], "warp")}
        </TabsContent>
        <TabsContent value="openvpn" className="mt-4">
          {renderEgressList(allEgress.openvpn, "openvpn")}
        </TabsContent>
        <TabsContent value="v2ray" className="mt-4">
          {renderEgressList(allEgress.v2ray, "v2ray")}
        </TabsContent>
      </Tabs>

      {/* Dialogs */}
      <AddWireGuardDialog open={showAddWireGuard} onOpenChange={setShowAddWireGuard} />
      <AddDirectDialog open={showAddDirect} onOpenChange={setShowAddDirect} />
      <AddWarpDialog open={showAddWarp} onOpenChange={setShowAddWarp} />
      <AddPIADialog 
        open={showAddPIA || !!editingPIA} 
        onOpenChange={(open) => { setShowAddPIA(open); if (!open) setEditingPIA(undefined); }}
        editProfile={editingPIA}
      />
      <PIALoginDialog 
        open={showPIALogin} 
        onOpenChange={setShowPIALogin}
        onSuccess={handlePIALoginSuccess}
      />
      <AddOpenVPNDialog
        open={showAddOpenVPN || !!editingOpenVPN}
        onOpenChange={(open) => { setShowAddOpenVPN(open); if (!open) setEditingOpenVPN(undefined); }}
        editEgress={editingOpenVPN}
      />
      <AddV2RayDialog
        open={showAddV2Ray || !!editingV2Ray}
        onOpenChange={(open) => { setShowAddV2Ray(open); if (!open) setEditingV2Ray(undefined); }}
        editEgress={editingV2Ray}
      />
    </div>
  );
}
