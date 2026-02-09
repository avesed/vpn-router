import { Handle, Position } from '@xyflow/react';
import { Globe, Shield, Zap } from 'lucide-react';

export function EgressNode({ data }: { data: any }) {
  const getIcon = () => {
    if (data.type === 'warp') return <Zap className="w-5 h-5 text-yellow-500" />;
    if (data.type === 'wireguard') return <Shield className="w-5 h-5 text-blue-500" />;
    return <Globe className="w-5 h-5 text-gray-500" />;
  };

  return (
    <div className="px-4 py-2 shadow-md rounded-md bg-card text-card-foreground border-2 border-muted w-40 text-center">
      <Handle type="target" position={Position.Left} className="w-3 h-3 bg-muted-foreground" />
      <div className="flex flex-col items-center justify-center">
        <div className="mb-1">{getIcon()}</div>
        <span className="font-bold text-sm truncate w-full">{data.label}</span>
        <span className="text-xs text-muted-foreground uppercase">{data.type}</span>
      </div>
    </div>
  );
}
