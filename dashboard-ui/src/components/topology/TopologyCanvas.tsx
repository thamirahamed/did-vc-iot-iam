import { useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  Panel,
  ReactFlowProvider,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type Node,
  type ReactFlowInstance,
} from "reactflow";
import { RotateCcw } from "lucide-react";
import CustomEdge, { type CustomEdgeData } from "./CustomEdge";
import FlowTooltip from "./FlowTooltip";
import TopologyNode, { type TopologyNodeData } from "./TopologyNode";
import type { DashboardDevice } from "../../types";

const nodeTypes = { topologyNode: TopologyNode };
const edgeTypes = { custom: CustomEdge };

function createInitialNodes(
  devices: DashboardDevice[],
  selectedDeviceId: string | undefined,
  onSelectDevice: (deviceId: string) => void,
): Node<TopologyNodeData>[] {
  return [
    {
      id: "devices",
      type: "topologyNode",
      position: { x: 60, y: 190 },
      data: {
        title: "IoT Devices Cluster",
        kind: "devices",
        items: [],
        devices,
        selectedDeviceId,
        onSelectDevice,
      },
    },
  {
    id: "issuer",
    type: "topologyNode",
    position: { x: 430, y: 60 },
    data: {
      title: "Issuer Service",
      kind: "issuer",
      items: [
        { label: "DID registration", color: "bg-blue" },
        { label: "Identity VC issuance", color: "bg-blue" },
        { label: "Capability VC issuance", color: "bg-blue" },
        { label: "Revocation management", color: "bg-orange" },
        { label: "Accumulator updates", color: "bg-orange" },
      ],
    },
  },
  {
    id: "verifier",
    type: "topologyNode",
    position: { x: 430, y: 350 },
    data: {
      title: "Verifier Service",
      kind: "verifier",
      items: [
        { label: "VC verification", color: "bg-green" },
        { label: "Proof of possession", color: "bg-green" },
        { label: "Capability authorization", color: "bg-green" },
        { label: "Accumulator proof check", color: "bg-cyan" },
        { label: "Decision engine", color: "bg-green" },
      ],
    },
  },
  {
    id: "queue",
    type: "topologyNode",
    position: { x: 780, y: 210 },
    data: {
      title: "Async Audit Queue",
      kind: "queue",
      items: [
        { label: "Non blocking audit mode", color: "bg-purple" },
        { label: "Pending 0", color: "bg-purple" },
      ],
    },
  },
  {
    id: "adapter",
    type: "topologyNode",
    position: { x: 1060, y: 230 },
    data: {
      title: "Fabric Adapter",
      kind: "adapter",
      items: [
        { label: "Long running adapter", color: "bg-cyan" },
        { label: "Peer CLI bridge", color: "bg-cyan" },
        { label: "Healthy", color: "bg-green" },
      ],
    },
  },
  {
    id: "ledger",
    type: "topologyNode",
    position: { x: 1360, y: 170 },
    data: {
      title: "Hyperledger Fabric IAM Ledger",
      subtitle: "IAM Chaincode",
      kind: "ledger",
      items: [
        "DID Registry",
        "Credential Status",
        "Accumulator State",
        "Audit Events",
      ],
    },
  },
  ];
}

const initialEdges: Edge<CustomEdgeData>[] = [
  edge(
    "devices-issuer",
    "devices",
    "issuer",
    "#3b82f6",
    "Identity and Issuance",
    "Device onboarding, DID registration, identity VC issuance, capability VC issuance, and accumulator proof creation.",
    "right",
    "left-target",
  ),
  edge(
    "issuer-devices",
    "issuer",
    "devices",
    "#3b82f6",
    "VC Delivery",
    "Issuer returns identity VC, capability VC, and accumulator proof to the device.",
    "left",
    "right-target",
  ),
  edge(
    "devices-verifier",
    "devices",
    "verifier",
    "#10b981",
    "Authorization Request",
    "Device presents VC and accumulator proof to verifier.",
    "right",
    "left-target",
  ),
  edge(
    "verifier-devices",
    "verifier",
    "devices",
    "#10b981",
    "Authorization Result",
    "Verifier returns allow or deny decision.",
    "left",
    "right-target",
  ),
  edge(
    "issuer-adapter",
    "issuer",
    "adapter",
    "#f97316",
    "Issuer Ledger Writes",
    "Issuer registers DID, writes credential status, revocation updates, and accumulator roots through the Fabric adapter.",
    "right",
    "left-target",
  ),
  edge(
    "verifier-adapter",
    "verifier",
    "adapter",
    "#00dce5",
    "Verifier Ledger Reads",
    "Verifier reads DID records and latest accumulator state through the Fabric adapter.",
    "right",
    "left-target",
    true,
  ),
  edge(
    "issuer-queue",
    "issuer",
    "queue",
    "#a855f7",
    "Issuer Audit",
    "Issuer sends DID registration, VC issuance, and revocation audit events to the non blocking audit queue.",
    "right",
    "left-target",
  ),
  edge(
    "verifier-queue",
    "verifier",
    "queue",
    "#a855f7",
    "Verifier Audit",
    "Verifier sends authorization allow and deny audit events to the non blocking audit queue.",
    "right",
    "left-target",
  ),
  edge(
    "queue-adapter",
    "queue",
    "adapter",
    "#a855f7",
    "Audit Write",
    "Queued audit events are written to Fabric asynchronously.",
    "right",
    "left-target",
  ),
  edge(
    "adapter-ledger",
    "adapter",
    "ledger",
    "#00dce5",
    "Chaincode Access",
    "The long running adapter performs query and invoke operations against IAM chaincode.",
    "right",
    "left-target",
  ),
];

type TopologyCanvasProps = {
  devices: DashboardDevice[];
  selectedDeviceId?: string;
  onSelectDevice: (deviceId: string) => void;
};

export default function TopologyCanvas({
  devices,
  selectedDeviceId,
  onSelectDevice,
}: TopologyCanvasProps) {
  return (
    <ReactFlowProvider>
      <TopologyCanvasInner
        devices={devices}
        selectedDeviceId={selectedDeviceId}
        onSelectDevice={onSelectDevice}
      />
    </ReactFlowProvider>
  );
}

function TopologyCanvasInner({
  devices,
  selectedDeviceId,
  onSelectDevice,
}: TopologyCanvasProps) {
  const initialNodes = useMemo(
    () => createInitialNodes(devices, selectedDeviceId, onSelectDevice),
    [devices, selectedDeviceId, onSelectDevice],
  );
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [rawEdges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [instance, setInstance] = useState<ReactFlowInstance | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<{
    x: number;
    y: number;
    title: string;
    body: string;
    color: string;
  } | null>(null);

  const edges = useMemo(
    () =>
      rawEdges.map((candidate) => {
        const connected =
          hoveredNode &&
          (candidate.source === hoveredNode || candidate.target === hoveredNode);
        return {
          ...candidate,
          data: {
            ...candidate.data!,
            active: Boolean(connected),
            muted: Boolean(hoveredNode && !connected),
          },
        };
      }),
    [hoveredNode, rawEdges],
  );

  const onConnect = (connection: Connection) => {
    setEdges((current) =>
      addEdge(
        {
          ...connection,
          type: "custom",
          animated: true,
          data: {
            color: "#00dce5",
            name: "Custom Link",
            tooltip: "Ad hoc dashboard link.",
          },
        },
        current,
      ),
    );
  };

  const resetLayout = () => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    requestAnimationFrame(() => instance?.fitView({ padding: 0.18, duration: 400 }));
  };

  useEffect(() => {
    setNodes((current) =>
      current.map((node) =>
        node.id === "devices"
          ? {
              ...node,
              data: {
                ...node.data,
                devices,
                selectedDeviceId,
                onSelectDevice,
              },
            }
          : node,
      ),
    );
  }, [devices, selectedDeviceId, onSelectDevice, setNodes]);

  return (
    <div className="relative h-[640px] w-full overflow-hidden border-b border-line/30 bg-background">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onInit={setInstance}
        onNodeMouseEnter={(_, node) => setHoveredNode(node.id)}
        onNodeMouseLeave={() => setHoveredNode(null)}
        onEdgeMouseEnter={(event, edge) =>
          setTooltip({
            x: event.clientX,
            y: event.clientY,
            title: edge.data?.name || "Topology Link",
            body: edge.data?.tooltip || "",
            color: edge.data?.color || "#00dce5",
          })
        }
        onEdgeMouseMove={(event, edge) =>
          setTooltip({
            x: event.clientX,
            y: event.clientY,
            title: edge.data?.name || "Topology Link",
            body: edge.data?.tooltip || "",
            color: edge.data?.color || "#00dce5",
          })
        }
        onEdgeMouseLeave={() => setTooltip(null)}
        fitView
        fitViewOptions={{ padding: 0.18 }}
        minZoom={0.45}
        maxZoom={1.65}
        panOnDrag
        nodesDraggable
        proOptions={{ hideAttribution: true }}
      >
        <Background
          color="rgba(49,67,84,0.32)"
          gap={40}
          variant={BackgroundVariant.Lines}
        />
        <Controls showInteractive={false} />
        <Panel position="top-right">
          <button
            type="button"
            onClick={resetLayout}
            className="flex items-center gap-2 rounded border border-line/50 bg-panel/90 px-3 py-2 font-mono text-xs text-muted backdrop-blur transition hover:text-text"
            title="Reset layout"
          >
            <RotateCcw size={14} /> Reset Layout
          </button>
        </Panel>
        <Panel position="bottom-right" className="!m-4">
          <div className="flex flex-col gap-2 rounded border border-line/40 bg-panel/90 px-3 py-3 font-mono text-[10px] uppercase text-muted backdrop-blur">
            <LegendDot color="bg-blue" label="Identity and Issuance" />
            <LegendDot color="bg-green" label="Authorization" />
            <LegendDot color="bg-orange" label="Revocation and Accumulator" />
            <LegendDot color="bg-purple" label="Async Audit" />
            <LegendDot color="bg-cyan" label="Fabric Access" />
          </div>
        </Panel>
      </ReactFlow>
      {tooltip ? (
        <FlowTooltip
          x={tooltip.x}
          y={tooltip.y}
          title={tooltip.title}
          body={tooltip.body}
          color={tooltip.color}
        />
      ) : null}
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2.5 whitespace-nowrap">
      <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${color}`} />
      <span>{label}</span>
    </div>
  );
}

function edge(
  id: string,
  source: string,
  target: string,
  color: string,
  name: string,
  tooltip: string,
  sourceHandle: string,
  targetHandle: string,
  dashed = false,
): Edge<CustomEdgeData> {
  return {
    id,
    source,
    target,
    sourceHandle,
    targetHandle,
    type: "custom",
    animated: true,
    data: { color, dashed, name, tooltip },
  };
}
