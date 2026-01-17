import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { RadioGroup, RadioGroupItem } from "../ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import { Loader2, Scale, ArrowRightLeft, Info } from "lucide-react";
import { useAvailableMembers } from "../../api/hooks/useOutboundGroups";
import type { OutboundGroup, OutboundGroupType, EcmpAlgorithm, AvailableMember } from "../../types";
import { ECMP_ALGORITHMS } from "../../types";

interface GroupCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editGroup?: OutboundGroup | null;
  onSubmit: (data: {
    tag: string;
    description?: string;
    type: OutboundGroupType;
    members: string[];
    weights?: Record<string, number>;
    algorithm?: EcmpAlgorithm;
    health_check_url?: string;
    health_check_interval?: number;
    health_check_timeout?: number;
  }) => Promise<void>;
  isSubmitting?: boolean;
}

const DEFAULT_HEALTH_CHECK_URL = "http://www.gstatic.com/generate_204";
const DEFAULT_HEALTH_CHECK_INTERVAL = 300;
const DEFAULT_HEALTH_CHECK_TIMEOUT = 5;

export function GroupCreateDialog({
  open,
  onOpenChange,
  editGroup,
  onSubmit,
  isSubmitting
}: GroupCreateDialogProps) {
  const { t } = useTranslation();
  const { data: availableData, isLoading: loadingMembers } = useAvailableMembers();

  // Form state
  const [tag, setTag] = useState("");
  const [description, setDescription] = useState("");
  const [groupType, setGroupType] = useState<OutboundGroupType>("loadbalance");
  const [selectedMembers, setSelectedMembers] = useState<string[]>([]);
  const [weights, setWeights] = useState<Record<string, number>>({});
  const [algorithm, setAlgorithm] = useState<EcmpAlgorithm>("five_tuple_hash");
  const [healthCheckUrl, setHealthCheckUrl] = useState(DEFAULT_HEALTH_CHECK_URL);
  const [healthCheckInterval, setHealthCheckInterval] = useState(DEFAULT_HEALTH_CHECK_INTERVAL);
  const [healthCheckTimeout, setHealthCheckTimeout] = useState(DEFAULT_HEALTH_CHECK_TIMEOUT);

  const isEditing = !!editGroup;
  const availableMembers = availableData?.members || [];

  // Reset form when dialog opens/closes or editGroup changes
  useEffect(() => {
    if (open) {
      if (editGroup) {
        setTag(editGroup.tag);
        setDescription(editGroup.description || "");
        setGroupType(editGroup.type);
        setSelectedMembers(editGroup.members || []);
        setWeights(editGroup.weights || {});
        setAlgorithm(editGroup.algorithm || "five_tuple_hash");
        setHealthCheckUrl(editGroup.health_check_url || DEFAULT_HEALTH_CHECK_URL);
        setHealthCheckInterval(editGroup.health_check_interval || DEFAULT_HEALTH_CHECK_INTERVAL);
        setHealthCheckTimeout(editGroup.health_check_timeout || DEFAULT_HEALTH_CHECK_TIMEOUT);
      } else {
        setTag("");
        setDescription("");
        setGroupType("loadbalance");
        setSelectedMembers([]);
        setWeights({});
        setAlgorithm("five_tuple_hash");
        setHealthCheckUrl(DEFAULT_HEALTH_CHECK_URL);
        setHealthCheckInterval(DEFAULT_HEALTH_CHECK_INTERVAL);
        setHealthCheckTimeout(DEFAULT_HEALTH_CHECK_TIMEOUT);
      }
    }
  }, [open, editGroup]);

  const handleMemberToggle = (memberTag: string) => {
    const isSelected = selectedMembers.includes(memberTag);
    if (isSelected) {
      // Remove member
      setSelectedMembers(prev => prev.filter(m => m !== memberTag));
      // Remove its weight
      setWeights(prev => {
        const newWeights = { ...prev };
        delete newWeights[memberTag];
        return newWeights;
      });
    } else {
      // Add member
      setSelectedMembers(prev => [...prev, memberTag]);
      // Add default weight
      setWeights(prev => ({ ...prev, [memberTag]: 1 }));
    }
  };

  const handleWeightChange = (memberTag: string, value: number) => {
    setWeights(prev => ({ ...prev, [memberTag]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedMembers.length < 2) return;

    await onSubmit({
      tag,
      description: description || undefined,
      type: groupType,
      members: selectedMembers,
      weights: groupType === "loadbalance" ? weights : undefined,
      algorithm: groupType === "loadbalance" ? algorithm : undefined,
      health_check_url: healthCheckUrl || undefined,
      health_check_interval: healthCheckInterval,
      health_check_timeout: healthCheckTimeout,
    });
  };

  const getMemberTypeBadge = (member: AvailableMember) => {
    const typeColors: Record<string, string> = {
      pia: "bg-blue-500/10 text-blue-500",
      wireguard: "bg-purple-500/10 text-purple-500",
      direct: "bg-green-500/10 text-green-500",
      openvpn: "bg-orange-500/10 text-orange-500",
      warp: "bg-amber-500/10 text-amber-500",
    };
    const colorClass = typeColors[member.type] || "bg-gray-500/10 text-gray-500";
    return (
      <Badge variant="outline" className={`text-xs ${colorClass}`}>
        {member.type.toUpperCase()}
      </Badge>
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>
            {isEditing ? t("groups.editGroup") : t("groups.addGroup")}
          </DialogTitle>
          <DialogDescription>
            {t("groups.subtitle")}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex-1 overflow-hidden flex flex-col">
          <ScrollArea className="flex-1 pr-4">
            <div className="space-y-6 pb-4">
              {/* Basic Info */}
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="tag">{t("groups.tag")}</Label>
                    <Input
                      id="tag"
                      value={tag}
                      onChange={(e) => setTag(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
                      placeholder={t("groups.tagPlaceholder")}
                      disabled={isEditing}
                      required
                    />
                    <p className="text-xs text-muted-foreground">{t("groups.tagHint")}</p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">{t("groups.description")}</Label>
                    <Input
                      id="description"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder={t("groups.descriptionPlaceholder")}
                    />
                  </div>
                </div>
              </div>

              {/* Group Type */}
              <div className="space-y-3">
                <Label>{t("groups.groupType")}</Label>
                <RadioGroup
                  value={groupType}
                  onValueChange={(v) => setGroupType(v as OutboundGroupType)}
                  className="grid grid-cols-2 gap-4"
                >
                  <Label
                    htmlFor="loadbalance"
                    className={`flex items-center gap-3 p-4 border rounded-lg cursor-pointer transition-colors ${
                      groupType === "loadbalance" ? "border-primary bg-primary/5" : "hover:bg-muted/50"
                    }`}
                  >
                    <RadioGroupItem value="loadbalance" id="loadbalance" />
                    <Scale className="h-5 w-5 text-blue-500" />
                    <div className="flex-1">
                      <p className="font-medium">{t("groups.loadbalance")}</p>
                      <p className="text-xs text-muted-foreground">{t("groups.loadbalanceDesc")}</p>
                    </div>
                  </Label>
                  <Label
                    htmlFor="failover"
                    className={`flex items-center gap-3 p-4 border rounded-lg cursor-pointer transition-colors ${
                      groupType === "failover" ? "border-primary bg-primary/5" : "hover:bg-muted/50"
                    }`}
                  >
                    <RadioGroupItem value="failover" id="failover" />
                    <ArrowRightLeft className="h-5 w-5 text-amber-500" />
                    <div className="flex-1">
                      <p className="font-medium">{t("groups.failover")}</p>
                      <p className="text-xs text-muted-foreground">{t("groups.failoverDesc")}</p>
                    </div>
                  </Label>
                </RadioGroup>
              </div>

              {/* Algorithm Selection (only for loadbalance) */}
              {groupType === "loadbalance" && (
                <div className="space-y-3">
                  <Label>{t("groups.algorithm")}</Label>
                  <Select
                    value={algorithm}
                    onValueChange={(v) => setAlgorithm(v as EcmpAlgorithm)}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder={t("groups.selectAlgorithm")} />
                    </SelectTrigger>
                    <SelectContent>
                      {ECMP_ALGORITHMS.map((alg) => (
                        <SelectItem key={alg.value} value={alg.value}>
                          <div className="flex flex-col">
                            <span>{alg.label}</span>
                            <span className="text-xs text-muted-foreground">{alg.description}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    {ECMP_ALGORITHMS.find(a => a.value === algorithm)?.description}
                  </p>
                </div>
              )}

              {/* Member Selection */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label>{t("groups.selectMembers")}</Label>
                  <span className="text-sm text-muted-foreground">
                    {selectedMembers.length} {t("groups.selected")}
                    {selectedMembers.length < 2 && (
                      <span className="text-destructive ml-2">({t("groups.minRequired")})</span>
                    )}
                  </span>
                </div>

                {loadingMembers ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                  </div>
                ) : availableMembers.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Info className="h-8 w-8 mx-auto mb-2" />
                    <p>{t("groups.noMembersAvailable")}</p>
                  </div>
                ) : (
                  <div className="border rounded-lg divide-y max-h-[200px] overflow-y-auto">
                    {availableMembers.map((member) => {
                      const isSelected = selectedMembers.includes(member.tag);
                      return (
                        <div
                          key={member.tag}
                          className={`flex items-center gap-3 p-3 cursor-pointer transition-colors ${
                            isSelected ? "bg-primary/5" : "hover:bg-muted/50"
                          }`}
                          onClick={() => handleMemberToggle(member.tag)}
                        >
                          <div
                            className="h-4 w-4 shrink-0 rounded-sm border border-primary shadow grid place-content-center data-[checked=true]:bg-primary data-[checked=true]:text-primary-foreground"
                            data-checked={isSelected}
                          >
                            {isSelected && <span className="text-xs">✓</span>}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium truncate">{member.tag}</span>
                              {getMemberTypeBadge(member)}
                            </div>
                            <p className="text-xs text-muted-foreground truncate">
                              {member.description}
                            </p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Weight Configuration (only for loadbalance) */}
              {groupType === "loadbalance" && selectedMembers.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Label>{t("groups.weights")}</Label>
                    <span className="text-xs text-muted-foreground">({t("groups.weightHint")})</span>
                  </div>
                  <div className="space-y-3 border rounded-lg p-3">
                    {selectedMembers.map((memberTag) => (
                      <div key={memberTag} className="flex items-center gap-4">
                        <span className="flex-1 text-sm truncate">{memberTag}</span>
                        <Input
                          type="number"
                          value={weights[memberTag] || 1}
                          onChange={(e) => handleWeightChange(memberTag, Math.max(1, Math.min(10, Number(e.target.value))))}
                          min={1}
                          max={10}
                          className="w-20 text-center"
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Health Check Configuration */}
              <div className="space-y-3">
                <Label>{t("groups.healthCheck")}</Label>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2 md:col-span-3">
                    <Label htmlFor="health_url" className="text-xs text-muted-foreground">
                      {t("groups.healthCheckUrl")}
                    </Label>
                    <Input
                      id="health_url"
                      value={healthCheckUrl}
                      onChange={(e) => setHealthCheckUrl(e.target.value)}
                      placeholder="http://www.gstatic.com/generate_204"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="interval" className="text-xs text-muted-foreground">
                      {t("groups.healthCheckInterval")}
                    </Label>
                    <Input
                      id="interval"
                      type="number"
                      value={healthCheckInterval}
                      onChange={(e) => setHealthCheckInterval(Number(e.target.value))}
                      min={10}
                      max={3600}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="timeout" className="text-xs text-muted-foreground">
                      {t("groups.healthCheckTimeout")}
                    </Label>
                    <Input
                      id="timeout"
                      type="number"
                      value={healthCheckTimeout}
                      onChange={(e) => setHealthCheckTimeout(Number(e.target.value))}
                      min={1}
                      max={30}
                    />
                  </div>
                </div>
              </div>
            </div>
          </ScrollArea>

          <DialogFooter className="pt-4 border-t">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              type="submit"
              disabled={isSubmitting || selectedMembers.length < 2 || !tag}
            >
              {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {isEditing ? t("common.save") : t("common.create")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
