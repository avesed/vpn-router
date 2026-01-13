import { EgressTabs } from "../components/egress/EgressTabs";

export default function EgressPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Egress</h1>
        <p className="text-muted-foreground">
          Manage your outbound connections including PIA, WireGuard, Direct, and WARP.
        </p>
      </div>
      <EgressTabs />
    </div>
  );
}
