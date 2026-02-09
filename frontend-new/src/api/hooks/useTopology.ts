import { usePeerNodes } from "./usePeerNodes";
import { useNodeChains } from "./useChains";
import { useAllEgress } from "./useEgress";
import { useMemo } from "react";
import type { Node, Edge } from "@xyflow/react";

export interface TopologyData {
  nodes: Node[];
  edges: Edge[];
}

export function useTopologyData() {
  const { data: peerData, isLoading: isPeerLoading } = usePeerNodes();
  const { data: chainData, isLoading: isChainLoading } = useNodeChains();
  const { data: egressData, isLoading: isEgressLoading } = useAllEgress();

  const topology = useMemo<TopologyData>(() => {
    if (!peerData || !chainData || !egressData) {
      return { nodes: [], edges: [] };
    }

    const nodes: Node[] = [];
    const edges: Edge[] = [];

    // 1. Gateway Node (Center)
    nodes.push({
      id: "gateway",
      type: "gateway",
      position: { x: 0, y: 0 },
      data: { label: "This Gateway" },
    });

    // 2. Peer Nodes (Left side)
    peerData.nodes.forEach((peer, index) => {
      const nodeId = `peer-${peer.tag}`;
      nodes.push({
        id: nodeId,
        type: "peer",
        position: { x: -250, y: index * 100 },
        data: { ...peer, label: peer.tag },
      });

      // Edge from Peer to Gateway
      edges.push({
        id: `edge-${nodeId}-gateway`,
        source: nodeId,
        target: "gateway",
        animated: peer.tunnel_status === "connected",
        style: { stroke: peer.tunnel_status === "connected" ? "#22c55e" : "#94a3b8" },
      });
    });

    // 3. Egress Nodes (Right side)
    // We need to handle different types of egress returned by getAllEgress
    // Assuming egressData is an array of egress objects with a 'tag' and 'type'
    const allEgress = Array.isArray(egressData) ? egressData : [];
    
    allEgress.forEach((egress, index) => {
      const nodeId = `egress-${egress.tag}`;
      nodes.push({
        id: nodeId,
        type: "egress",
        position: { x: 250, y: index * 100 },
        data: { ...egress, label: egress.tag },
      });
    });

    // 4. Chains (Edges from Gateway to Egress or between Egresses?)
    // Chains usually define a path. For simplicity in this visualization, 
    // we might show edges from Gateway to the first hop of a chain, or if it's a simple egress, to that egress.
    
    // However, without detailed chain structure (hops), we can link Gateway to Egresses directly for now,
    // or visualize chains as specific paths.
    
    // Let's iterate through chains to see active routes
    // For now, let's just connect Gateway to all Egresses to show availability
    // In a real topology, we'd want to show active routing rules.
    // Given the instructions "Visual network graph showing: This Gateway (center) -> Peer Nodes -> Exit Egresses",
    // it seems Peers connect to Gateway, and Gateway connects to Egresses.
    
    allEgress.forEach((egress) => {
        const nodeId = `egress-${egress.tag}`;
        edges.push({
            id: `edge-gateway-${nodeId}`,
            source: "gateway",
            target: nodeId,
            animated: false, // Could be animated if traffic is flowing
            style: { stroke: "#94a3b8" },
        });
    });

    return { nodes, edges };
  }, [peerData, chainData, egressData]);

  return {
    data: topology,
    isLoading: isPeerLoading || isChainLoading || isEgressLoading,
  };
}
