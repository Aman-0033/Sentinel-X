import React, { useState, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  Node,
  Edge,
  MarkerType,
  Handle,
  Position,
  NodeProps,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Shield,
  Server,
  Laptop,
  Skull,
  Globe,
  Database,
  Info,
  Activity,
  Layers,
  Lock,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';

// Custom Network Nodes
const HostNode: React.FC<NodeProps> = ({ data }) => {
  const isMalicious = data.status === 'COMPROMISED';
  return (
    <div
      className={`bg-[#121216] border-2 rounded-xl p-3 min-w-[140px] text-center shadow-lg transition-all ${
        isMalicious
          ? 'border-[#FF2D95] shadow-glow-rose'
          : 'border-[#007BA7] shadow-glow-cerulean'
      }`}
    >
      <Handle type="target" position={Position.Left} className={isMalicious ? '!bg-[#FF2D95]' : '!bg-[#007BA7]'} />
      <Handle type="source" position={Position.Right} className={isMalicious ? '!bg-[#FF2D95]' : '!bg-[#007BA7]'} />
      <div className="flex items-center justify-center gap-1.5 mb-1">
        {data.icon === 'database' ? (
          <Database className="w-4 h-4 text-[#007BA7]" />
        ) : data.icon === 'skull' ? (
          <Skull className="w-4 h-4 text-[#FF2D95] animate-pulse" />
        ) : (
          <Server className="w-4 h-4 text-[#007BA7]" />
        )}
        <span
          className={`text-[9px] font-mono font-bold uppercase tracking-wider ${
            isMalicious ? 'text-[#FF2D95]' : 'text-[#007BA7]'
          }`}
        >
          {data.subnet || 'NODE'}
        </span>
      </div>
      <p className="text-xs font-mono font-bold text-[#F8FAFC]">{data.ip}</p>
      <p className="text-[10px] text-[#94A3B8] truncate">{data.hostname}</p>
    </div>
  );
};

const GatewayNode: React.FC<NodeProps> = ({ data }) => {
  return (
    <div className="bg-[#121216] border-2 border-amber-500 rounded-xl p-3 min-w-[140px] text-center shadow-lg">
      <Handle type="target" position={Position.Left} className="!bg-amber-500" />
      <Handle type="source" position={Position.Right} className="!bg-amber-500" />
      <div className="flex items-center justify-center gap-1.5 mb-1 text-amber-400">
        <Shield className="w-4 h-4" />
        <span className="text-[9px] font-mono font-bold uppercase tracking-wider">CORE FIREWALL</span>
      </div>
      <p className="text-xs font-mono font-bold text-[#F8FAFC]">{data.ip}</p>
      <p className="text-[10px] text-[#94A3B8]">Ingress Inspection</p>
    </div>
  );
};

const nodeTypes = {
  hostNode: HostNode,
  gatewayNode: GatewayNode,
};

export const NetworkTopology: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<{
    ip: string;
    hostname: string;
    subnet: string;
    status: string;
    openPorts: string[];
    flows: number;
  } | null>({
    ip: '198.51.100.42',
    hostname: 'ext-c2-adversary.ru',
    subnet: 'EXTERNAL INTERNET',
    status: 'COMPROMISED',
    openPorts: ['54122/TCP', '6667/TCP'],
    flows: 482,
  });

  const nodes: Node[] = useMemo(
    () => [
      {
        id: 'ext-1',
        type: 'hostNode',
        position: { x: 30, y: 150 },
        data: {
          ip: '198.51.100.42',
          hostname: 'adversary-bot.ru',
          subnet: 'EXTERNAL',
          status: 'COMPROMISED',
          icon: 'skull',
          openPorts: ['54122/TCP', '6667/TCP'],
          flows: 482,
        },
      },
      {
        id: 'ext-2',
        type: 'hostNode',
        position: { x: 30, y: 320 },
        data: {
          ip: '203.0.113.88',
          hostname: 'ssh-scanner.cn',
          subnet: 'EXTERNAL',
          status: 'COMPROMISED',
          icon: 'skull',
          openPorts: ['43901/TCP'],
          flows: 245,
        },
      },
      {
        id: 'fw-1',
        type: 'gatewayNode',
        position: { x: 320, y: 230 },
        data: {
          ip: '10.0.0.1',
          hostname: 'sentinel-perimeter-fw',
          subnet: 'PERIMETER',
          status: 'SAFE',
          openPorts: ['80', '443', '22'],
          flows: 14200,
        },
      },
      {
        id: 'dmz-web-1',
        type: 'hostNode',
        position: { x: 600, y: 100 },
        data: {
          ip: '10.0.1.50',
          hostname: 'nginx-ingress-01',
          subnet: 'DMZ WEB',
          status: 'SAFE',
          icon: 'server',
          openPorts: ['80/TCP', '443/TCP'],
          flows: 8400,
        },
      },
      {
        id: 'dmz-ssh-1',
        type: 'hostNode',
        position: { x: 600, y: 260 },
        data: {
          ip: '10.0.1.22',
          hostname: 'bastion-host-01',
          subnet: 'DMZ BASTION',
          status: 'SAFE',
          icon: 'server',
          openPorts: ['22/TCP'],
          flows: 1540,
        },
      },
      {
        id: 'db-1',
        type: 'hostNode',
        position: { x: 880, y: 180 },
        data: {
          ip: '10.0.2.80',
          hostname: 'postgres-primary',
          subnet: 'DATABASE',
          status: 'SAFE',
          icon: 'database',
          openPorts: ['5432/TCP'],
          flows: 3200,
        },
      },
    ],
    []
  );

  const edges: Edge[] = useMemo(
    () => [
      // Malicious edges (Neon Rose #FF2D95)
      {
        id: 'e-ext1-fw',
        source: 'ext-1',
        target: 'fw-1',
        animated: true,
        label: 'DDoS SYN-Flood (96.4 Risk)',
        style: { stroke: '#FF2D95', strokeWidth: 2.5 },
        labelStyle: { fill: '#FF2D95', fontFamily: 'monospace', fontSize: 10, fontWeight: 700 },
        labelBgStyle: { fill: '#121216', stroke: '#FF2D95' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#FF2D95' },
      },
      {
        id: 'e-ext2-fw',
        source: 'ext-2',
        target: 'fw-1',
        animated: true,
        label: 'SSH BruteForce (88.5 Risk)',
        style: { stroke: '#FF2D95', strokeWidth: 2.5 },
        labelStyle: { fill: '#FF2D95', fontFamily: 'monospace', fontSize: 10, fontWeight: 700 },
        labelBgStyle: { fill: '#121216', stroke: '#FF2D95' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#FF2D95' },
      },
      // Normal safe edges (Cerulean Blue #007BA7)
      {
        id: 'e-fw-web',
        source: 'fw-1',
        target: 'dmz-web-1',
        label: 'HTTP/S Reverse Proxy',
        style: { stroke: '#007BA7', strokeWidth: 1.5 },
        labelStyle: { fill: '#007BA7', fontFamily: 'monospace', fontSize: 10 },
        labelBgStyle: { fill: '#121216', stroke: '#1E293B' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#007BA7' },
      },
      {
        id: 'e-fw-ssh',
        source: 'fw-1',
        target: 'dmz-ssh-1',
        label: 'MFA SSH Ingress',
        style: { stroke: '#007BA7', strokeWidth: 1.5 },
        labelStyle: { fill: '#007BA7', fontFamily: 'monospace', fontSize: 10 },
        labelBgStyle: { fill: '#121216', stroke: '#1E293B' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#007BA7' },
      },
      {
        id: 'e-web-db',
        source: 'dmz-web-1',
        target: 'db-1',
        label: 'Secure SQL Connection Pool',
        style: { stroke: '#007BA7', strokeWidth: 1.5 },
        labelStyle: { fill: '#007BA7', fontFamily: 'monospace', fontSize: 10 },
        labelBgStyle: { fill: '#121216', stroke: '#1E293B' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#007BA7' },
      },
    ],
    []
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
            <span>NETWORK TOPOLOGY & THREAT MAPPING</span>
          </h2>
          <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
            React Flow interactive topology displaying perimeter gateways, subnets, and live intrusion paths
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FF2D95] shadow-glow-rose"></span>
            <span className="text-[#94A3B8]">Malicious Path (#FF2D95)</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#007BA7] shadow-glow-cerulean"></span>
            <span className="text-[#94A3B8]">Safe Telemetry (#007BA7)</span>
          </span>
        </div>
      </div>

      {/* Main Canvas + Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Full React Flow Topology Canvas (3 cols) */}
        <div className="lg:col-span-3 bg-[#0A0A0A] border border-[#1E293B] rounded-xl h-[560px] overflow-hidden relative shadow-soc-card">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            onNodeClick={(_, node) => {
              setSelectedNode(node.data as any);
            }}
          >
            <Background color="#1E293B" gap={24} size={1} />
            <Controls />
          </ReactFlow>
        </div>

        {/* Node Inspector Drawer (1 col) */}
        <Card className="flex flex-col justify-between">
          <div>
            <CardHeader
              title="Asset Inspector"
              subtitle="Select any node to view real-time port telemetry"
              icon={<Info className="w-5 h-5 text-[#007BA7]" />}
            />

            {selectedNode ? (
              <div className="space-y-4 font-mono text-xs">
                <div>
                  <span className="text-[#94A3B8] uppercase text-[10px]">Host IP Address</span>
                  <p className="text-white font-bold text-sm mt-0.5">{selectedNode.ip}</p>
                  <p className="text-[#94A3B8] text-[11px]">{selectedNode.hostname}</p>
                </div>

                <div>
                  <span className="text-[#94A3B8] uppercase text-[10px]">Segment / Subnet</span>
                  <p className="text-[#007BA7] font-semibold mt-0.5">{selectedNode.subnet}</p>
                </div>

                <div>
                  <span className="text-[#94A3B8] uppercase text-[10px]">Threat Posture</span>
                  <div className="mt-1">
                    <Badge
                      severity={selectedNode.status === 'COMPROMISED' ? 'CRITICAL' : 'BENIGN'}
                      showDot
                    >
                      {selectedNode.status}
                    </Badge>
                  </div>
                </div>

                <div>
                  <span className="text-[#94A3B8] uppercase text-[10px]">Listening Ports</span>
                  <div className="flex flex-wrap gap-1.5 mt-1.5">
                    {selectedNode.openPorts?.map((p) => (
                      <span
                        key={p}
                        className="px-2 py-0.5 bg-[#0A0A0A] border border-[#1E293B] text-[#F8FAFC] rounded text-[10px]"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-[#94A3B8] uppercase text-[10px]">Recorded Ingress Flows</span>
                  <p className="text-white font-bold mt-0.5">{selectedNode.flows.toLocaleString()}</p>
                </div>
              </div>
            ) : (
              <p className="text-xs text-[#94A3B8] font-mono py-8 text-center">
                Click on any node in the topology canvas to inspect telemetry.
              </p>
            )}
          </div>

          <div className="pt-4 border-t border-[#1E293B] text-[11px] font-mono text-[#94A3B8]">
            Topology auto-refreshed via active flow telemetry.
          </div>
        </Card>
      </div>
    </div>
  );
};
