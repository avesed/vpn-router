import { useState, useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "../ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";
import { Check, ChevronsUpDown, Loader2 } from "lucide-react";
import { cn } from "../../lib/utils";
import { usePIARegions, useAddPIALine, useUpdatePIALine, usePIALogin, usePIAStatus } from "../../api/hooks/usePIA";
import { Alert, AlertDescription } from "../ui/alert";
import { AlertCircle } from "lucide-react";
import type { VpnProfile, PiaRegion } from "../../types";

interface AddPIADialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editProfile?: VpnProfile;
}

export function AddPIADialog({ open, onOpenChange, editProfile }: AddPIADialogProps) {
  const { t } = useTranslation();
  const { data: regionsData, isLoading: regionsLoading } = usePIARegions();
  const { data: piaStatus } = usePIAStatus();
  const addLine = useAddPIALine();
  const updateLine = useUpdatePIALine();

  const [tag, setTag] = useState("");
  const [description, setDescription] = useState("");
  const [regionId, setRegionId] = useState("");
  const [customDns, setCustomDns] = useState("");
  const [regionOpen, setRegionOpen] = useState(false);

  const isEditing = !!editProfile;

  // Reset form when dialog opens/closes or edit profile changes
  useEffect(() => {
    if (open) {
      if (editProfile) {
        setTag(editProfile.tag);
        setDescription(editProfile.description || "");
        setRegionId(editProfile.region_id);
        setCustomDns(editProfile.custom_dns || "");
      } else {
        setTag("");
        setDescription("");
        setRegionId("");
        setCustomDns("");
      }
    }
  }, [open, editProfile]);

  // Group regions by country
  const regionsByCountry = useMemo(() => {
    if (!regionsData?.regions) return {};
    return regionsData.regions.reduce((acc, region) => {
      const country = ["CN", "HK", "TW"].includes(region.country) 
        ? t("egress.pia.chinaGroup", { defaultValue: "China/HK/TW" })
        : region.country;
      if (!acc[country]) acc[country] = [];
      acc[country].push(region);
      return acc;
    }, {} as Record<string, PiaRegion[]>);
  }, [regionsData, t]);

  const selectedRegion = useMemo(() => {
    return regionsData?.regions.find(r => r.id === regionId);
  }, [regionsData, regionId]);

  const handleSubmit = async () => {
    if (!tag.trim() || !regionId) return;

    try {
      if (isEditing) {
        await updateLine.mutateAsync({
          tag: editProfile.tag,
          data: {
            description: description || tag,
            region_id: regionId,
            custom_dns: customDns || undefined
          }
        });
      } else {
        await addLine.mutateAsync({
          tag: tag.trim(),
          description: description || tag.trim(),
          regionId,
          customDns: customDns || undefined
        });
      }
      onOpenChange(false);
    } catch {
      // Error handled by mutation
    }
  };

  const isSubmitting = addLine.isPending || updateLine.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {isEditing 
              ? t("egress.pia.editTitle", { defaultValue: "Edit PIA Profile" })
              : t("egress.pia.addTitle", { defaultValue: "Add PIA Profile" })}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Login warning */}
          {!isEditing && !piaStatus?.has_credentials && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                {t("egress.pia.notLoggedInWarning", { 
                  defaultValue: "You are not logged in to PIA. The profile will be created but won't be functional until you login." 
                })}
              </AlertDescription>
            </Alert>
          )}

          {/* Tag */}
          <div className="space-y-2">
            <Label htmlFor="tag">{t("common.tag", { defaultValue: "Tag" })}</Label>
            <Input
              id="tag"
              value={tag}
              onChange={(e) => setTag(e.target.value)}
              placeholder="pia-us-west"
              disabled={isEditing}
            />
            <p className="text-xs text-muted-foreground">
              {t("egress.pia.tagHint", { defaultValue: "Unique identifier (lowercase letters, numbers, hyphens)" })}
            </p>
          </div>

          {/* Description */}
          <div className="space-y-2">
            <Label htmlFor="description">{t("common.description", { defaultValue: "Description" })}</Label>
            <Input
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder={t("egress.pia.descriptionPlaceholder", { defaultValue: "US West Coast" })}
            />
          </div>

          {/* Region Selector */}
          <div className="space-y-2">
            <Label>{t("egress.pia.region", { defaultValue: "Region" })}</Label>
            <Popover open={regionOpen} onOpenChange={setRegionOpen}>
              <PopoverTrigger asChild>
                <Button
                  variant="outline"
                  role="combobox"
                  aria-expanded={regionOpen}
                  className="w-full justify-between"
                  disabled={regionsLoading}
                >
                  {regionsLoading ? (
                    <span className="flex items-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      {t("common.loading", { defaultValue: "Loading..." })}
                    </span>
                  ) : selectedRegion ? (
                    <span>{selectedRegion.name} ({selectedRegion.country})</span>
                  ) : (
                    <span className="text-muted-foreground">
                      {t("egress.pia.selectRegion", { defaultValue: "Select a region..." })}
                    </span>
                  )}
                  <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-[400px] p-0" align="start">
                <Command>
                  <CommandInput placeholder={t("egress.pia.searchRegion", { defaultValue: "Search regions..." })} />
                  <CommandList>
                    <CommandEmpty>{t("egress.pia.noRegion", { defaultValue: "No region found." })}</CommandEmpty>
                    {Object.entries(regionsByCountry).map(([country, regions]) => (
                      <CommandGroup key={country} heading={country}>
                        {regions.map((region) => (
                          <CommandItem
                            key={region.id}
                            value={`${region.name} ${region.id} ${region.country}`}
                            onSelect={() => {
                              setRegionId(region.id);
                              setRegionOpen(false);
                            }}
                          >
                            <Check
                              className={cn(
                                "mr-2 h-4 w-4",
                                regionId === region.id ? "opacity-100" : "opacity-0"
                              )}
                            />
                            <span className="flex-1">{region.name}</span>
                            {region.port_forward && (
                              <span className="text-xs text-green-500 ml-2">Port Forward</span>
                            )}
                            {region.geo && (
                              <span className="text-xs text-blue-500 ml-2">Geo</span>
                            )}
                          </CommandItem>
                        ))}
                      </CommandGroup>
                    ))}
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>
          </div>

          {/* Custom DNS */}
          <div className="space-y-2">
            <Label htmlFor="customDns">
              {t("egress.pia.customDns", { defaultValue: "Custom DNS (optional)" })}
            </Label>
            <Input
              id="customDns"
              value={customDns}
              onChange={(e) => setCustomDns(e.target.value)}
              placeholder="8.8.8.8"
            />
            <p className="text-xs text-muted-foreground">
              {t("egress.pia.customDnsHint", { defaultValue: "Leave empty to use PIA's DNS servers" })}
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button 
            onClick={handleSubmit} 
            disabled={!tag.trim() || !regionId || isSubmitting}
          >
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {isEditing 
              ? t("common.save", { defaultValue: "Save" })
              : t("common.add", { defaultValue: "Add" })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// Login Modal for PIA credentials
interface PIALoginDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

export function PIALoginDialog({ open, onOpenChange, onSuccess }: PIALoginDialogProps) {
  const { t } = useTranslation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  
  const login = usePIALogin();

  const handleLogin = async () => {
    if (!username || !password) return;
    
    try {
      await login.mutateAsync({ username, password });
      setUsername("");
      setPassword("");
      onOpenChange(false);
      onSuccess?.();
    } catch {
      // Error handled by mutation
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {t("egress.pia.loginTitle", { defaultValue: "PIA Login" })}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="pia-username">
              {t("egress.pia.username", { defaultValue: "Username" })}
            </Label>
            <Input
              id="pia-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={t("egress.pia.usernamePlaceholder", { defaultValue: "p1234567" })}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="pia-password">
              {t("egress.pia.password", { defaultValue: "Password" })}
            </Label>
            <Input
              id="pia-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t("egress.pia.loginHint", { 
              defaultValue: "Enter your PIA credentials. These are stored securely and used to connect to PIA servers." 
            })}
          </p>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel", { defaultValue: "Cancel" })}
          </Button>
          <Button 
            onClick={handleLogin}
            disabled={!username || !password || login.isPending}
          >
            {login.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t("egress.pia.login", { defaultValue: "Login" })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
