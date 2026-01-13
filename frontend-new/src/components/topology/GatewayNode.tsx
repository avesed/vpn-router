import { Handle, Position } from '@xyflow/react';
import { Router } from 'lucide-react';

export function GatewayNode({ data }: { data: { label: string } }) {
  return (
    <div className="px-4 py-2 shadow-md rounded-md bg-primary text-primary-foreground border-2 border-primary w-40 text-center">
      <Handle type="target" position={Position.Left} className="w-3 h-3 bg-muted-foreground" />
      <div className="flex flex-col items-center justify-center">
        <Router className="w-6 h-6 mb-1" />
        <span className="font-bold text-sm">{data.label}</span>
      </div>
      <Handle type="source" position={Position.Right} className="w-3 h-3 bg-muted-foreground" />
    </div>
  );
}
