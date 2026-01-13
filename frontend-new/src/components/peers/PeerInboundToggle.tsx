import { Switch } from "@/components/ui/switch";
import { useEnablePeerInbound, useDisablePeerInbound } from "@/api/hooks/usePeerNodes";
import type { PeerNode } from "@/types";

interface PeerInboundToggleProps {
  peer: PeerNode;
}

export function PeerInboundToggle({ peer }: PeerInboundToggleProps) {
  const enableInbound = useEnablePeerInbound();
  const disableInbound = useDisablePeerInbound();

  const handleToggle = (checked: boolean) => {
    if (checked) {
      enableInbound.mutate({ tag: peer.tag });
    } else {
      disableInbound.mutate(peer.tag);
    }
  };

  const isLoading = enableInbound.isPending || disableInbound.isPending;

  return (
    <div className="flex items-center space-x-2">
      <Switch
        checked={!!peer.inbound_enabled}
        onCheckedChange={handleToggle}
        disabled={isLoading}
      />
      {peer.inbound_enabled ? (
        <span className="text-xs text-muted-foreground">
          Port: {peer.inbound_port}
        </span>
      ) : null}
    </div>
  );
}
