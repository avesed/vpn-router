import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useTranslation } from "react-i18next";
import {
  ReactFlow,
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Position,
  Handle
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ArrowPathIcon,
  XMarkIcon,
  ServerIcon,
  ServerStackIcon,
  GlobeAltIcon,
  SignalIcon,
  SignalSlashIcon,
  ClockIcon,
  ExclamationCircleIcon,
  CheckCircleIcon,
  InformationCircleIcon
} from "@heroicons/react/24/outline";
import { api } from "../api/client";
import type { PeerNode, NodeChain, PeerTunnelStatus } from "../types";

// Status color mapping for edges
const statusEdgeColors: Record<string, string> = {
  connected: "#22c55e", // green
  connecting: "#eab308", // yellow
  disconnected: "#64748b", // gray
  error: "#ef4444" // red
};

// Status colors for node styling
const statusNodeColors: Record<PeerTunnelStatus, { bg: string; border: string; text: string }> = {
  connected: { bg: "bg-blue-500/20", border: "border-blue-500", text: "text-blue-400" },
  connecting: { bg: "bg-yellow-500/20", border: "border-yellow-500", text: "text-yellow-400" },
  disconnected: { bg: "bg-slate-500/20", border: "border-slate-500", text: "text-slate-400" },
  error: { bg: "bg-red-500/20", border: "border-red-500", text: "text-red-400" }
};

// Health colors for chain nodes (moved to module level for performance)
const healthColors: Record<string, { bg: string; border: string; text: string }> = {
  healthy: { bg: "bg-emerald-500/20", border: "border-emerald-500", text: "text-emerald-400" },
  degraded: { bg: "bg-amber-500/20", border: "border-amber-500", text: "text-amber-400" },
  unhealthy: { bg: "bg-rose-500/20", border: "border-rose-500", text: "text-rose-400" },
  unknown: { bg: "bg-slate-500/20", border: "border-slate-500", text: "text-slate-400" }
};

// Custom node components
interface LocalGatewayNodeData {
  label: string;
  subtitle?: string;
}

const LocalGatewayNode = React.memo(function LocalGatewayNode({ data }: { data: LocalGatewayNodeData }) {
  const { t } = useTranslation();
  return (
    <div className="relative">
      <Handle type="source" position={Position.Right} className="!bg-emerald-500 !w-3 !h-3" />
      <div className="px-6 py-4 rounded-2xl bg-gradient-to-br from-emerald-500/30 to-emerald-600/20 border-2 border-emerald-500 shadow-lg shadow-emerald-500/20 min-w-[160px]">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-emerald-500/30">
            <ServerStackIcon className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <div className="text-white font-bold text-sm">{data.label}</div>
            <div className="text-emerald-300 text-xs">{data.subtitle || t("topology.thisInstance")}</div>
          </div>
        </div>
      </div>
    </div>
  );
});

interface PeerNodeData {
  node: PeerNode;
  onClick: () => void;
}

const PeerNodeComponent = React.memo(function PeerNodeComponent({ data }: { data: PeerNodeData }) {
  const { t } = useTranslation();
  const { node, onClick } = data;
  const colors = statusNodeColors[node.tunnel_status] || statusNodeColors.disconnected;

  const StatusIcon = node.tunnel_status === "connected"
    ? SignalIcon
    : node.tunnel_status === "connecting"
    ? ClockIcon
    : node.tunnel_status === "error"
    ? ExclamationCircleIcon
    : SignalSlashIcon;

  return (
    <div className="relative cursor-pointer" onClick={onClick}>
      <Handle type="target" position={Position.Left} className="!bg-blue-500 !w-3 !h-3" />
      <Handle type="source" position={Position.Right} className="!bg-blue-500 !w-3 !h-3" />
      <div className={`px-4 py-3 rounded-xl ${colors.bg} border-2 ${colors.border} shadow-lg min-w-[140px] transition-transform hover:scale-105`}>
        <div className="flex items-center gap-2 mb-1">
          <ServerIcon className={`w-4 h-4 ${colors.text}`} />
          <span className="text-white font-medium text-sm truncate max-w-[100px]">{node.name}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <StatusIcon className={`w-3.5 h-3.5 ${colors.text}`} />
          <span className={`text-xs ${colors.text}`}>{t(`peers.status.${node.tunnel_status}`)}</span>
        </div>
        <div className="text-xs text-slate-500 mt-1 truncate">
          {node.tunnel_type === "wireguard" ? "WireGuard" : `Xray (${node.xray_protocol?.toUpperCase()})`}
        </div>
      </div>
    </div>
  );
});

interface ChainNodeData {
  chain: NodeChain;
  onClick: () => void;
}

const ChainNodeComponent = React.memo(function ChainNodeComponent({ data }: { data: ChainNodeData }) {
  const { t } = useTranslation();
  const { chain, onClick } = data;
  const colors = healthColors[chain.health_status] || healthColors.unknown;

  return (
    <div className="relative cursor-pointer" onClick={onClick}>
      <Handle type="target" position={Position.Left} className="!bg-purple-500 !w-3 !h-3" />
      <Handle type="source" position={Position.Right} className="!bg-purple-500 !w-3 !h-3" />
      <div className={`px-4 py-3 rounded-xl ${colors.bg} border-2 ${colors.border} shadow-lg min-w-[140px] transition-transform hover:scale-105`}>
        <div className="flex items-center gap-2 mb-1">
          <GlobeAltIcon className={`w-4 h-4 ${colors.text}`} />
          <span className="text-white font-medium text-sm truncate max-w-[100px]">{chain.name}</span>
        </div>
        <div className="text-xs text-slate-400">
          {t("chains.hopCount", { count: chain.hops?.length || 0 })}
        </div>
        <div className={`text-xs ${colors.text} mt-1`}>
          {t(`chains.status.${chain.health_status}`)}
        </div>
      </div>
    </div>
  );
});

// Node types for React Flow
const nodeTypes = {
  localGateway: LocalGatewayNode,
  peerNode: PeerNodeComponent,
  chainNode: ChainNodeComponent
};

// Simple layout algorithm using dagre-like positioning
function layoutNodes(
  peerNodes: PeerNode[],
  chains: NodeChain[]
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Center node - Local Gateway
  const centerX = 400;
  const centerY = 300;

  nodes.push({
    id: "local-gateway",
    type: "localGateway",
    position: { x: centerX, y: centerY },
    data: { label: "Local Gateway" }
  });

  // Position peer nodes in a semi-circle around the gateway
  const peerRadius = 280;
  const peerStartAngle = -Math.PI / 2; // Start from top
  const peerAngleSpan = Math.PI; // Spread across 180 degrees (right side)

  peerNodes.forEach((node, index) => {
    const angle = peerStartAngle + (peerAngleSpan * (index + 1)) / (peerNodes.length + 1);
    const x = centerX + peerRadius * Math.cos(angle) + 200;
    const y = centerY + peerRadius * Math.sin(angle);

    nodes.push({
      id: `peer-${node.tag}`,
      type: "peerNode",
      position: { x, y },
      data: { node, onClick: () => {} } // onClick will be set later
    });

    // Edge from gateway to peer
    edges.push({
      id: `edge-gateway-${node.tag}`,
      source: "local-gateway",
      target: `peer-${node.tag}`,
      style: {
        stroke: statusEdgeColors[node.tunnel_status] || statusEdgeColors.disconnected,
        strokeWidth: 2
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: statusEdgeColors[node.tunnel_status] || statusEdgeColors.disconnected
      },
      animated: node.tunnel_status === "connecting"
    });
  });

  // Position chains on the left side
  const chainStartY = centerY - (chains.length * 80) / 2;

  chains.forEach((chain, index) => {
    const x = centerX - 350;
    const y = chainStartY + index * 100;

    nodes.push({
      id: `chain-${chain.tag}`,
      type: "chainNode",
      position: { x, y },
      data: { chain, onClick: () => {} }
    });

    // Edge from chain to gateway
    const healthEdgeColor = chain.health_status === "healthy"
      ? "#22c55e"
      : chain.health_status === "degraded"
      ? "#eab308"
      : chain.health_status === "unhealthy"
      ? "#ef4444"
      : "#64748b";

    edges.push({
      id: `edge-chain-${chain.tag}`,
      source: `chain-${chain.tag}`,
      target: "local-gateway",
      style: {
        stroke: healthEdgeColor,
        strokeWidth: 2,
        strokeDasharray: chain.enabled ? "0" : "5,5"
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: healthEdgeColor
      }
    });
  });

  return { nodes, edges };
}

export default function TopologyView() {
  const { t } = useTranslation();
  const [peerNodes, setPeerNodes] = useState<PeerNode[]>([]);
  const [chains, setChains] = useState<NodeChain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<PeerNode | null>(null);
  const [selectedChain, setSelectedChain] = useState<NodeChain | null>(null);
  const [showLegend, setShowLegend] = useState(true);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  // Load data from API
  const loadData = useCallback(async () => {
    try {
      setError(null);
      const [nodesRes, chainsRes] = await Promise.all([
        api.getPeerNodes(),
        api.getNodeChains()
      ]);
      setPeerNodes(nodesRes.nodes || []);
      setChains(chainsRes.chains || []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : t("common.loadFailed");
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    loadData();
    // Auto-refresh every 15 seconds
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Escape key handler for modals
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (selectedNode) setSelectedNode(null);
        else if (selectedChain) setSelectedChain(null);
      }
    };

    if (selectedNode || selectedChain) {
      document.addEventListener("keydown", handleEscape);
      return () => document.removeEventListener("keydown", handleEscape);
    }
  }, [selectedNode, selectedChain]);

  // Update layout when data changes
  useEffect(() => {
    const { nodes: layoutedNodes, edges: layoutedEdges } = layoutNodes(peerNodes, chains);

    // Update click handlers
    const nodesWithHandlers = layoutedNodes.map(node => {
      if (node.type === "peerNode") {
        const peerNode = peerNodes.find(p => `peer-${p.tag}` === node.id);
        return {
          ...node,
          data: {
            ...node.data,
            onClick: () => peerNode && setSelectedNode(peerNode)
          }
        };
      }
      if (node.type === "chainNode") {
        const chain = chains.find(c => `chain-${c.tag}` === node.id);
        return {
          ...node,
          data: {
            ...node.data,
            onClick: () => chain && setSelectedChain(chain)
          }
        };
      }
      return node;
    });

    setNodes(nodesWithHandlers);
    setEdges(layoutedEdges);
  }, [peerNodes, chains, setNodes, setEdges]);

  // Calculate stats
  const stats = useMemo(() => {
    const connectedPeers = peerNodes.filter(n => n.tunnel_status === "connected").length;
    const healthyChains = chains.filter(c => c.health_status === "healthy").length;
    return {
      totalPeers: peerNodes.length,
      connectedPeers,
      totalChains: chains.length,
      healthyChains
    };
  }, [peerNodes, chains]);

  if (loading && nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-[600px]">
        <ArrowPathIcon className="w-8 h-8 text-slate-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">{t("topology.title")}</h1>
          <p className="text-slate-400 mt-1">{t("topology.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowLegend(!showLegend)}
            aria-label={t("topology.legend")}
            aria-pressed={showLegend}
            className={`px-3 py-2 rounded-lg flex items-center gap-2 transition-colors ${
              showLegend ? "bg-brand/20 text-brand" : "bg-slate-700 text-slate-300 hover:bg-slate-600"
            }`}
          >
            <InformationCircleIcon className="w-4 h-4" />
            <span className="hidden sm:inline">{t("topology.legend")}</span>
          </button>
          <button
            onClick={loadData}
            disabled={loading}
            aria-label={t("common.refresh")}
            className="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <ArrowPathIcon className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            <span className="hidden sm:inline">{t("common.refresh")}</span>
          </button>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-slate-800/50 rounded-xl p-3 border border-white/5">
          <div className="text-slate-400 text-xs mb-1">{t("topology.totalPeers")}</div>
          <div className="text-xl font-bold text-white">{stats.totalPeers}</div>
        </div>
        <div className="bg-slate-800/50 rounded-xl p-3 border border-white/5">
          <div className="text-slate-400 text-xs mb-1">{t("topology.connectedPeers")}</div>
          <div className="text-xl font-bold text-emerald-400">{stats.connectedPeers}</div>
        </div>
        <div className="bg-slate-800/50 rounded-xl p-3 border border-white/5">
          <div className="text-slate-400 text-xs mb-1">{t("topology.totalChains")}</div>
          <div className="text-xl font-bold text-white">{stats.totalChains}</div>
        </div>
        <div className="bg-slate-800/50 rounded-xl p-3 border border-white/5">
          <div className="text-slate-400 text-xs mb-1">{t("topology.healthyChains")}</div>
          <div className="text-xl font-bold text-emerald-400">{stats.healthyChains}</div>
        </div>
      </div>

      {/* Topology canvas */}
      <div className="relative h-[500px] md:h-[600px] bg-slate-800/30 rounded-2xl border border-white/10 overflow-hidden">
        {nodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center p-8">
            <ServerStackIcon className="w-16 h-16 text-slate-600 mb-4" />
            <h3 className="text-lg font-medium text-slate-400 mb-2">{t("topology.noNodes")}</h3>
            <p className="text-slate-500 text-sm max-w-md">{t("topology.noNodesHint")}</p>
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.3}
            maxZoom={1.5}
            defaultEdgeOptions={{
              style: { strokeWidth: 2 }
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#334155" gap={20} size={1} />
            <Controls className="!bg-slate-800 !border-slate-600 !rounded-lg [&_button]:!bg-slate-700 [&_button]:!border-slate-600 [&_button:hover]:!bg-slate-600 [&_button_svg]:!fill-slate-300" />
            <MiniMap
              nodeColor={(node) => {
                if (node.type === "localGateway") return "#10b981";
                if (node.type === "chainNode") return "#a855f7";
                return "#3b82f6";
              }}
              maskColor="rgba(15, 23, 42, 0.8)"
              className="!bg-slate-800/90 !border-slate-600 !rounded-lg"
            />
          </ReactFlow>
        )}

        {/* Legend overlay */}
        {showLegend && (
          <div className="absolute top-4 left-4 bg-slate-800/95 backdrop-blur-sm rounded-xl p-4 border border-white/10 shadow-xl max-w-xs">
            <h4 className="text-white font-medium mb-3 flex items-center gap-2">
              <InformationCircleIcon className="w-4 h-4 text-brand" />
              {t("topology.legend")}
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-emerald-500" />
                <span className="text-slate-300">{t("topology.legendGateway")}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span className="text-slate-300">{t("topology.legendPeer")}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-purple-500" />
                <span className="text-slate-300">{t("topology.legendChain")}</span>
              </div>
              <hr className="border-slate-600 my-2" />
              <div className="flex items-center gap-2">
                <div className="w-6 h-0.5 bg-green-500" />
                <span className="text-slate-400">{t("topology.legendConnected")}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-6 h-0.5 bg-yellow-500" />
                <span className="text-slate-400">{t("topology.legendConnecting")}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-6 h-0.5 bg-slate-500" />
                <span className="text-slate-400">{t("topology.legendDisconnected")}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-6 h-0.5 bg-red-500" />
                <span className="text-slate-400">{t("topology.legendError")}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Peer Node Detail Modal */}
      {selectedNode && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="peer-modal-title"
            className="bg-slate-800 rounded-xl w-full max-w-md"
          >
            <div className="flex items-center justify-between p-4 border-b border-slate-700">
              <h2 id="peer-modal-title" className="text-lg font-semibold text-white">{t("peers.nodeDetails")}</h2>
              <button
                onClick={() => setSelectedNode(null)}
                aria-label={t("common.close")}
                className="p-1 text-slate-400 hover:text-white transition-colors"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("peers.name")}</label>
                  <p className="text-white">{selectedNode.name}</p>
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("peers.tag")}</label>
                  <p className="text-white font-mono text-sm">{selectedNode.tag}</p>
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">{t("peers.endpoint")}</label>
                <p className="text-white font-mono text-sm">{selectedNode.endpoint}</p>
              </div>
              {selectedNode.description && (
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("peers.description")}</label>
                  <p className="text-slate-300">{selectedNode.description}</p>
                </div>
              )}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("peers.tunnelStatus")}</label>
                  <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
                    statusNodeColors[selectedNode.tunnel_status].bg
                  } ${statusNodeColors[selectedNode.tunnel_status].text}`}>
                    {selectedNode.tunnel_status === "connected" ? (
                      <CheckCircleIcon className="w-3.5 h-3.5" />
                    ) : selectedNode.tunnel_status === "connecting" ? (
                      <ClockIcon className="w-3.5 h-3.5" />
                    ) : selectedNode.tunnel_status === "error" ? (
                      <ExclamationCircleIcon className="w-3.5 h-3.5" />
                    ) : (
                      <SignalSlashIcon className="w-3.5 h-3.5" />
                    )}
                    {t(`peers.status.${selectedNode.tunnel_status}`)}
                  </span>
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("peers.tunnelType")}</label>
                  <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
                    selectedNode.tunnel_type === "wireguard" ? "bg-blue-500/20 text-blue-400" : "bg-purple-500/20 text-purple-400"
                  }`}>
                    {selectedNode.tunnel_type === "wireguard" ? "WireGuard" : `Xray (${selectedNode.xray_protocol?.toUpperCase()})`}
                  </span>
                </div>
              </div>
              {selectedNode.tunnel_status === "connected" && selectedNode.tunnel_interface && (
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("peers.tunnelInterface")}</label>
                  <p className="text-white font-mono text-sm">{selectedNode.tunnel_interface}</p>
                </div>
              )}
              {selectedNode.last_error && (
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("peers.lastError")}</label>
                  <p className="text-red-400 text-sm">{selectedNode.last_error}</p>
                </div>
              )}
            </div>
            <div className="flex justify-end p-4 border-t border-slate-700">
              <button
                onClick={() => setSelectedNode(null)}
                className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
              >
                {t("common.close")}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Chain Detail Modal */}
      {selectedChain && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="chain-modal-title"
            className="bg-slate-800 rounded-xl w-full max-w-md"
          >
            <div className="flex items-center justify-between p-4 border-b border-slate-700">
              <h2 id="chain-modal-title" className="text-lg font-semibold text-white">{t("chains.title")}</h2>
              <button
                onClick={() => setSelectedChain(null)}
                aria-label={t("common.close")}
                className="p-1 text-slate-400 hover:text-white transition-colors"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("chains.name")}</label>
                  <p className="text-white">{selectedChain.name}</p>
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("chains.tag")}</label>
                  <p className="text-white font-mono text-sm">{selectedChain.tag}</p>
                </div>
              </div>
              {selectedChain.description && (
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("chains.description")}</label>
                  <p className="text-slate-300">{selectedChain.description}</p>
                </div>
              )}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("chains.healthStatus")}</label>
                  <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
                    selectedChain.health_status === "healthy" ? "bg-emerald-500/20 text-emerald-400" :
                    selectedChain.health_status === "degraded" ? "bg-amber-500/20 text-amber-400" :
                    selectedChain.health_status === "unhealthy" ? "bg-rose-500/20 text-rose-400" :
                    "bg-slate-500/20 text-slate-400"
                  }`}>
                    {t(`chains.status.${selectedChain.health_status}`)}
                  </span>
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{t("chains.priority")}</label>
                  <p className="text-white">{selectedChain.priority}</p>
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">{t("chains.hops")}</label>
                <div className="flex flex-wrap gap-2">
                  {selectedChain.hops?.map((hop, index) => {
                    const nodeName = peerNodes.find(n => n.tag === hop)?.name || hop;
                    const protocol = selectedChain.hop_protocols?.[hop] || "wireguard";
                    return (
                      <div key={index} className="flex items-center gap-1">
                        {index > 0 && <span className="text-slate-500">-&gt;</span>}
                        <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">
                          {nodeName}
                        </span>
                        <span className="text-slate-600 text-xs">({protocol})</span>
                      </div>
                    );
                  })}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                  selectedChain.enabled ? "bg-emerald-500/20 text-emerald-400" : "bg-slate-500/20 text-slate-400"
                }`}>
                  {selectedChain.enabled ? t("chains.enabled") : t("chains.disabled")}
                </span>
              </div>
            </div>
            <div className="flex justify-end p-4 border-t border-slate-700">
              <button
                onClick={() => setSelectedChain(null)}
                className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
              >
                {t("common.close")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
