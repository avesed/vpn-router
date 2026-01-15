import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "../ui/command";
import { useCommandPalette } from "./CommandPaletteProvider";
import { 
  LayoutDashboard, 
  Network, 
  Share2, 
  Link, 
  Shield, 
  Globe, 
  Server,
  Zap,
} from "lucide-react";
import { usePeerNodes, useConnectPeerNode, useDisconnectPeerNode } from "../../api/hooks/usePeerNodes";
import { useAllEgress, useTestEgress } from "../../api/hooks/useEgress";

export function CommandPalette() {
  const { open, setOpen } = useCommandPalette();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [query, setQuery] = useState("");

  // Data hooks
  const { data: peerData } = usePeerNodes();
  const { data: egressData } = useAllEgress();
  
  // Mutations
  const connectPeer = useConnectPeerNode();
  const disconnectPeer = useDisconnectPeerNode();
  const testEgress = useTestEgress();

  const runCommand = (command: () => void) => {
    setOpen(false);
    command();
  };

  const peers = peerData?.nodes || [];
  const egressList = Array.isArray(egressData) ? egressData : [];

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput
        placeholder={t("commandPalette.placeholder")}
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        <CommandEmpty>{t("commandPalette.noResults")}</CommandEmpty>
        
        <CommandGroup heading={t("commandPalette.navigation")}>
          <CommandItem onSelect={() => runCommand(() => navigate("/"))}>
            <LayoutDashboard className="mr-2 h-4 w-4" />
            {t("nav.dashboard")}
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/topology"))}>
            <Network className="mr-2 h-4 w-4" />
            {t("nav.topology")}
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/peers"))}>
            <Share2 className="mr-2 h-4 w-4" />
            {t("nav.peerNodes")}
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/chains"))}>
            <Link className="mr-2 h-4 w-4" />
            {t("nav.nodeChains")}
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/egress"))}>
            <Globe className="mr-2 h-4 w-4" />
            {t("nav.egress")}
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/rules"))}>
            <Shield className="mr-2 h-4 w-4" />
            {t("nav.routeRules")}
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/domain-catalog"))}>
            <Globe className="mr-2 h-4 w-4" />
            {t("nav.ruleCatalog")}
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading={t("commandPalette.peers")}>
          {peers.map((peer) => (
            <CommandItem 
              key={peer.tag} 
              onSelect={() => {
                if (peer.tunnel_status === "connected") {
                  runCommand(() => disconnectPeer.mutate(peer.tag));
                } else {
                  runCommand(() => connectPeer.mutate(peer.tag));
                }
              }}
            >
              <Server className="mr-2 h-4 w-4" />
              {peer.tag}
              <span className="ml-2 text-xs text-muted-foreground">
                {peer.tunnel_status === "connected" ? t("peers.disconnect") : t("peers.connect")}
              </span>
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading={t("commandPalette.egressActions")}>
          {egressList.map((egress) => (
            <CommandItem 
              key={egress.tag} 
              onSelect={() => runCommand(() => testEgress.mutate({ tag: egress.tag }))}
            >
              <Zap className="mr-2 h-4 w-4" />
              {t("commandPalette.testEgress", { tag: egress.tag })}
              <span className="ml-2 text-xs text-muted-foreground uppercase">
                {egress.type}
              </span>
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
