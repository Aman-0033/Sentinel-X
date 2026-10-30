import React, { useMemo } from 'react';
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
import { Shield, Server, Laptop, Skull, Globe } from 'lucide-react';
import { cn } from '../../utils/cn';

// Custom Attacker Node (Neon Rose #FF2D95)
const AttackerNodeComponent: React.FC<NodeProps> = ({ data }) => {
  return (
    <div className="bg-[#121216] border-2 border-[#FF2D95] rounded-xl p-3 min-w-[150px] shadow-glow-rose text-center relative">
      <Handle type="source" position={Position.Right} className="!bg-[#FF2D95] !w-2.5 !h-2.5" />
      <div className="flex items-center justify-center gap-1.5 text-[#FF2D95] mb-1">
        <Skull className="w-4 h-4 animate-pulse" />
        <span className="text-[10px] font-mono font-bold uppercase tracking-wider">MALICIOUS ACTOR</span>
      </div>
      <p className="text-xs font-mono font-bold text-[#F8FAFC]">{data.ip}</p>
      {data.label && <p className="text-[10px] text-[#94A3B8] mt-0.5">{data.label}</p>}
    </div>
  );
};

// Custom Clean Target Node (Cerulean Blue #007BA7)
const TargetNodeComponent: React.FC<NodeProps> = ({ data }) => {
  return (
    <div className="bg-[#121216] border-2 border-[#007BA7] rounded-xl p-3 min-w-[150px] shadow-glow-cerulean text-center relative">
      <Handle type="target" position={Position.Left} className="!bg-[#007BA7] !w-2.5 !h-2.5" />
      <Handle type="source" position={Position.Right} className="!bg-[#007BA7] !w-2.5 !h-2.5" />
      <div className="flex items-center justify-center gap-1.5 text-[#007BA7] mb-1">
        <Server className="w-4 h-4" />
        <span className="text-[10px] font-mono font-bold uppercase tracking-wider">PROTECTED ASSET</span>
      </div>
      <p className="text-xs font-mono font-bold text-[#F8FAFC]">{data.ip}</p>
      {data.label && <p className="text-[10px] text-[#94A3B8] mt-0.5">{data.label}</p>}
    </div>
  );
};

// Gateway / Firewall Node
const GatewayNodeComponent: React.FC<NodeProps> = ({ data }) => {
  return (
    <div className="bg-[#121216] border border-[#1E293B] rounded-xl p-3 min-w-[140px] text-center relative">
      <Handle type="target" position={Position.Left} className="!bg-[#94A3B8] !w-2 !h-2" />
      <Handle type="source" position={Position.Right} className="!bg-[#94A3B8] !w-2 !h-2" />
      <div className="flex items-center justify-center gap-1.5 text-amber-400 mb-1">
        <Shield className="w-4 h-4" />
        <span className="text-[10px] font-mono font-bold uppercase tracking-wider">GATEWAY FW</span>
      </div>
      <p className="text-xs font-mono text-[#F8FAFC]">{data.label || 'Perimeter Shield'}</p>
    </div>
  );
};

const nodeTypes = {
  attackerNode: AttackerNodeComponent,
  targetNode: TargetNodeComponent,
  gatewayNode: GatewayNodeComponent,
};

interface AttackGraphProps {
  sourceIp?: string;
  targetIp?: string;
  attackType?: string;
  height?: number;
}

export const AttackGraph: React.FC<AttackGraphProps> = ({
  sourceIp = '198.51.100.42',
  targetIp = '10.0.1.50',
  attackType = 'DDoS SYN-Flood',
  height = 320,
}) => {
  const nodes: Node[] = useMemo(
    () => [
      {
        id: 'node-attacker',
        type: 'attackerNode',
        position: { x: 50, y: 110 },
        data: { ip: sourceIp, label: 'External Ingress' },
      },
      {
        id: 'node-gateway',
        type: 'gatewayNode',
        position: { x: 300, y: 110 },
        data: { label: 'Perimeter Inspection' },
      },
      {
        id: 'node-target',
        type: 'targetNode',
        position: { x: 550, y: 110 },
        data: { ip: targetIp, label: 'Web Cluster (Target)' },
      },
      {
        id: 'node-db',
        type: 'targetNode',
        position: { x: 800, y: 110 },
        data: { ip: '10.0.2.80', label: 'Backend Database' },
      },
    ],
    [sourceIp, targetIp]
  );

  const edges: Edge[] = useMemo(
    () => [
      {
        id: 'edge-1',
        source: 'node-attacker',
        target: 'node-gateway',
        animated: true,
        label: attackType,
        style: { stroke: '#FF2D95', strokeWidth: 2.5 },
        labelStyle: { fill: '#FF2D95', fontFamily: 'monospace', fontSize: 11, fontWeight: 600 },
        labelBgStyle: { fill: '#121216', stroke: '#FF2D95', strokeWidth: 1 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#FF2D95',
        },
      },
      {
        id: 'edge-2',
        source: 'node-gateway',
        target: 'node-target',
        animated: true,
        label: 'Threat Filtered Ingress',
        style: { stroke: '#FF2D95', strokeWidth: 2, strokeDasharray: '5,5' },
        labelStyle: { fill: '#FF2D95', fontFamily: 'monospace', fontSize: 10 },
        labelBgStyle: { fill: '#121216', stroke: '#1E293B' },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#FF2D95',
        },
      },
      {
        id: 'edge-3',
        source: 'node-target',
        target: 'node-db',
        style: { stroke: '#007BA7', strokeWidth: 1.5 },
        label: 'Safe Internal RPC',
        labelStyle: { fill: '#007BA7', fontFamily: 'monospace', fontSize: 10 },
        labelBgStyle: { fill: '#121216', stroke: '#007BA7' },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#007BA7',
        },
      },
    ],
    [attackType]
  );

  return (
    <div style={{ width: '100%', height }} className="bg-[#0A0A0A] border border-[#1E293B] rounded-xl overflow-hidden relative">
      <div className="absolute top-3 left-3 z-10 flex items-center gap-3 bg-[#121216]/90 border border-[#1E293B] px-3 py-1.5 rounded-lg text-xs font-mono text-[#94A3B8]">
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#FF2D95] shadow-glow-rose"></span>
          <span>Malicious Edge (#FF2D95)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#007BA7] shadow-glow-cerulean"></span>
          <span>Safe Asset (#007BA7)</span>
        </span>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        attributionPosition="bottom-right"
      >
        <Background color="#1E293B" gap={20} size={1} />
        <Controls />
      </ReactFlow>
    </div>
  );
};
