import { useDefaultOutbound, useSwitchDefaultOutbound } from "../../api/hooks/useRules";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Label } from "../ui/label";
import { toast } from "sonner";
import { useEffect, useState } from "react";

export function DefaultOutboundSelect() {
  const { data, isLoading } = useDefaultOutbound();
  const switchOutbound = useSwitchDefaultOutbound();
  const [value, setValue] = useState("");

  useEffect(() => {
    if (data?.outbound) {
      setValue(data.outbound);
    }
  }, [data]);

  const handleValueChange = (newValue: string) => {
    setValue(newValue);
    toast.promise(switchOutbound.mutateAsync(newValue), {
      loading: "Switching default outbound...",
      success: "Default outbound switched",
      error: "Failed to switch outbound",
    });
  };

  if (isLoading || !data) return <div>Loading...</div>;

  return (
    <div className="flex items-center gap-4 p-4 border rounded-lg bg-card">
      <Label className="min-w-[120px]">Default Outbound</Label>
      <Select value={value} onValueChange={handleValueChange} disabled={switchOutbound.isPending}>
        <SelectTrigger className="w-[300px]">
          <SelectValue placeholder="Select default outbound" />
        </SelectTrigger>
        <SelectContent>
          {data.available_outbounds.map((outbound) => (
            <SelectItem key={outbound} value={outbound}>
              {outbound}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-sm text-muted-foreground">
        Traffic not matching any rule will use this outbound.
      </p>
    </div>
  );
}
