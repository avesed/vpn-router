import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAllEgress, useDeleteCustomEgress, useDeleteDirectEgress, useDeleteWarpEgress } from "../../api/hooks/useEgress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/tabs";
import { EgressCard } from "./EgressCard";
import { Button } from "../ui/button";
import { Plus, Loader2 } from "lucide-react";
import { AddWireGuardDialog } from "./AddWireGuardDialog";
import { AddDirectDialog } from "./AddDirectDialog";
import { AddWarpDialog } from "./AddWarpDialog";
import { toast } from "sonner";
import type { EgressItem } from "../../types";

export function EgressTabs() {
  const { t } = useTranslation();
  const { data: allEgress, isLoading, error } = useAllEgress();
  const deleteCustom = useDeleteCustomEgress();
  const deleteDirect = useDeleteDirectEgress();
  const deleteWarp = useDeleteWarpEgress();

  const [activeTab, setActiveTab] = useState("pia");
  const [showAddWireGuard, setShowAddWireGuard] = useState(false);
  const [showAddDirect, setShowAddDirect] = useState(false);
  const [showAddWarp, setShowAddWarp] = useState(false);

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
      default:
        return;
    }

    toast.promise(promise, {
      loading: t("egress.deleting"),
      success: t("egress.deleteSuccess"),
      error: t("egress.deleteFailed"),
    });
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
            onDelete={type !== "pia" && type !== "openvpn" && type !== "v2ray" ? (tag) => handleDelete(type, tag) : undefined}
            showActions={true}
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
          {renderEgressList(allEgress.pia, "PIA")}
        </TabsContent>
        <TabsContent value="custom" className="mt-4">
          {renderEgressList(allEgress.custom, "WireGuard")}
        </TabsContent>
        <TabsContent value="direct" className="mt-4">
          {renderEgressList(allEgress.direct, t("common.direct"))}
        </TabsContent>
        <TabsContent value="warp" className="mt-4">
          {renderEgressList(allEgress.warp || [], "WARP")}
        </TabsContent>
        <TabsContent value="openvpn" className="mt-4">
          {renderEgressList(allEgress.openvpn, "OpenVPN")}
        </TabsContent>
        <TabsContent value="v2ray" className="mt-4">
          {renderEgressList(allEgress.v2ray, "V2Ray")}
        </TabsContent>
      </Tabs>

      <AddWireGuardDialog open={showAddWireGuard} onOpenChange={setShowAddWireGuard} />
      <AddDirectDialog open={showAddDirect} onOpenChange={setShowAddDirect} />
      <AddWarpDialog open={showAddWarp} onOpenChange={setShowAddWarp} />
    </div>
  );
}
