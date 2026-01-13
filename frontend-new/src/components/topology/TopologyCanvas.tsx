import { useEffect } from 'react';
import { ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState, ConnectionMode } from '@xyflow/react';
import type { Node, Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { GatewayNode } from './GatewayNode';
import { PeerNode } from './PeerNode';
import { EgressNode } from './EgressNode';

const nodeTypes = {
  gateway: GatewayNode,
  peer: PeerNode,
  egress: EgressNode,
};

interface TopologyCanvasProps {
  nodes: Node[];
  edges: Edge[];
}

export function TopologyCanvas({ nodes: initialNodes, edges: initialEdges }: TopologyCanvasProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  return (
    <div className="h-[600px] w-full border rounded-lg bg-background">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        connectionMode={ConnectionMode.Loose}
        fitView
      >
        <Background />
        <Controls />
        <MiniMap zoomable pannable />
      </ReactFlow>
    </div>
  );
}
