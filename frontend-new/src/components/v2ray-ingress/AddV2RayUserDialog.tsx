import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAddV2RayUser } from "@/api/hooks/useV2RayIngress";
import { Loader2 } from "lucide-react";
import { VLESS_FLOW_OPTIONS } from "@/types";

const addUserSchema = z.object({
  name: z.string().min(1, "Name is required").regex(/^[a-zA-Z0-9_-]+$/, "Name can only contain letters, numbers, underscores and dashes"),
  email: z.string().email("Invalid email address").optional().or(z.literal("")),
  uuid: z.string().uuid("Invalid UUID").optional().or(z.literal("")),
  flow: z.string().optional(),
});

interface AddV2RayUserDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AddV2RayUserDialog({ open, onOpenChange }: AddV2RayUserDialogProps) {
  const { mutate: addUser, isPending } = useAddV2RayUser();

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors },
  } = useForm<{ name: string; email?: string; uuid?: string; flow?: string }>({
    resolver: zodResolver(addUserSchema),
  });

  const onSubmit = (data: { name: string; email?: string; uuid?: string; flow?: string }) => {
    addUser(
      {
        name: data.name,
        email: data.email || undefined,
        uuid: data.uuid || undefined,
        flow: data.flow || undefined,
      },
      {
        onSuccess: () => {
          reset();
          onOpenChange(false);
        },
      }
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add V2Ray User</DialogTitle>
          <DialogDescription>
            Create a new user for V2Ray ingress.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="name">Username</Label>
            <Input
              id="name"
              {...register("name")}
              placeholder="e.g. user1"
            />
            {errors.name && (
              <p className="text-sm text-destructive">{errors.name.message}</p>
            )}
          </div>

          <div className="grid gap-2">
            <Label htmlFor="email">Email (Optional)</Label>
            <Input
              id="email"
              type="email"
              {...register("email")}
              placeholder="user@example.com"
            />
            {errors.email && (
              <p className="text-sm text-destructive">{errors.email.message}</p>
            )}
          </div>

          <div className="grid gap-2">
            <Label htmlFor="uuid">UUID (Optional)</Label>
            <Input
              id="uuid"
              {...register("uuid")}
              placeholder="Leave empty to generate automatically"
            />
            {errors.uuid && (
              <p className="text-sm text-destructive">{errors.uuid.message}</p>
            )}
          </div>

          <div className="grid gap-2">
            <Label htmlFor="flow">Flow (XTLS Vision)</Label>
            <Select
              onValueChange={(value) => setValue("flow", value)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select flow..." />
              </SelectTrigger>
              <SelectContent>
                {VLESS_FLOW_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Add User
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
