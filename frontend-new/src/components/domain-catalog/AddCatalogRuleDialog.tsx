import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Label } from "../ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Input } from "../ui/input";
import { useAllEgress } from "../../api/hooks/useEgress";
import { Loader2 } from "lucide-react";

interface AddCatalogRuleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  categoryName: string;
  categoryId: string;
  type: "domain" | "ip";
  onSubmit: (outbound: string, tag: string) => void;
  isSubmitting: boolean;
}

export function AddCatalogRuleDialog({
  open,
  onOpenChange,
  categoryName,
  categoryId,
  type,
  onSubmit,
  isSubmitting,
}: AddCatalogRuleDialogProps) {
  const { data: egressData } = useAllEgress();
  const [outbound, setOutbound] = useState<string>("");
  const [tag, setTag] = useState<string>(`rule-${categoryId}`);

  const handleSubmit = () => {
    if (outbound) {
      onSubmit(outbound, tag);
    }
  };

  const outbounds = Array.isArray(egressData) ? egressData : [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Rule for {categoryName}</DialogTitle>
          <DialogDescription>
            Route traffic for {type === "domain" ? "domains in" : "IPs in"} {categoryName} through a specific outbound.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label htmlFor="tag">Rule Tag</Label>
            <Input
              id="tag"
              value={tag}
              onChange={(e) => setTag(e.target.value)}
              placeholder="e.g., rule-google"
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="outbound">Outbound Interface</Label>
            <Select value={outbound} onValueChange={setOutbound}>
              <SelectTrigger id="outbound">
                <SelectValue placeholder="Select outbound" />
              </SelectTrigger>
              <SelectContent>
                {outbounds.map((egress) => (
                  <SelectItem key={egress.tag} value={egress.tag}>
                    {egress.tag} ({egress.type})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!outbound || isSubmitting}>
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Create Rule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
