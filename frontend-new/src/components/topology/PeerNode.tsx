import { Handle, Position } from '@xyflow/react';
import { Laptop } from 'lucide-react';

export function PeerNode({ data }: { data: any }) {
  const isConnected = data.status === 'connected';
  
  return (
    <div className={`px-4 py-2 shadow-md rounded-md border-2 w-40 text-center bg-card text-card-foreground ${isConnected ? 'border-green-500' : 'border-muted'}`}>
      <div className="flex flex-col items-center justify-center">
        <Laptop className={`w-6 h-6 mb-1 ${isConnected ? 'text-green-500' : 'text-muted-foreground'}`} />
        <span className="font-bold text-sm truncate w-full">{data.label}</span>
        <span className="text-xs text-muted-foreground">{data.ip}</span>
      </div>
      <Handle type="source" position={Position.Right} className={`w-3 h-3 ${isConnected ? 'bg-green-500' : 'bg-muted-foreground'}`} />
    </div>
  );
}
