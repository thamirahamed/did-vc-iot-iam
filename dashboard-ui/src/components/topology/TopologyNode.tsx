import { Handle, Position, type NodeProps } from "reactflow";
import {
  BadgeCheck,
  Cable,
  Database,
  RadioTower,
  Router,
  ShieldCheck,
} from "lucide-react";
import type { DashboardDevice } from "../../types";

export type TopologyNodeData = {
  title: string;
  subtitle?: string;
  kind: "devices" | "issuer" | "verifier" | "queue" | "adapter" | "ledger";
  items: Array<string | { label: string; color: string }>;
  devices?: DashboardDevice[];
  selectedDeviceId?: string;
  onSelectDevice?: (deviceId: string) => void;
  selected?: boolean;
};

const iconMap = {
  devices: Router,
  issuer: BadgeCheck,
  verifier: ShieldCheck,
  queue: RadioTower,
  adapter: Cable,
  ledger: Database,
};

const toneMap = {
  devices: "border-cyan/45 text-cyan shadow-glow",
  issuer: "border-blue/45 text-blue",
  verifier: "border-green/45 text-green",
  queue: "border-purple/45 text-purple shadow-glow-purple",
  adapter: "border-cyan/35 text-cyan",
  ledger: "border-cyan/55 text-cyan shadow-glow",
};

const widthMap = {
  devices: "w-[280px]",
  issuer: "w-[260px]",
  verifier: "w-[260px]",
  queue: "w-[240px]",
  adapter: "w-[230px]",
  ledger: "w-[300px]",
};

export default function TopologyNode({ data, selected }: NodeProps<TopologyNodeData>) {
  const Icon = iconMap[data.kind];
  const isLedger = data.kind === "ledger";
  const isDevices = data.kind === "devices";

  return (
    <div
      className={`relative ${widthMap[data.kind]} rounded border bg-panel/95 p-3 backdrop-blur transition ${
        toneMap[data.kind]
      } ${selected || data.selected ? "ring-2 ring-cyan/70" : ""}`}
    >
      <NodeHandles />
      <div className="mb-3 flex items-center gap-2 border-b border-line/35 pb-2">
        <div className="flex h-8 w-8 items-center justify-center rounded border border-current/40 bg-background/60">
          <Icon size={17} />
        </div>
        <div className="min-w-0">
          <div className="truncate font-mono text-xs text-text">{data.title}</div>
          {data.subtitle ? (
            <div className="font-mono text-[10px] uppercase text-cyan">
              {data.subtitle}
            </div>
          ) : null}
        </div>
      </div>
      {isDevices ? (
        <div className="space-y-2">
          {(data.devices || []).map((device) => {
            const selectedDevice = data.selectedDeviceId === device.id;
            return (
              <button
                key={device.id}
                type="button"
                onClick={(event) => {
                  event.stopPropagation();
                  data.onSelectDevice?.(device.id);
                }}
                className={`w-full rounded border px-2 py-2 text-left transition ${
                  selectedDevice
                    ? "border-cyan/70 bg-cyan/10"
                    : "border-line/25 bg-background/55 hover:border-cyan/40"
                }`}
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="truncate font-mono text-[11px] text-text">
                    {device.label}
                  </span>
                  <span className={`font-mono text-[9px] uppercase ${statusText(device.status)}`}>
                    {device.status}
                  </span>
                </div>
                <div className="mt-1 truncate font-mono text-[10px] text-muted">
                  {device.did ? shortDid(device.did) : device.error || "DID pending"}
                </div>
              </button>
            );
          })}
          {!data.devices?.length ? (
            <div className="rounded border border-line/25 bg-background/55 px-2 py-2 font-mono text-[11px] text-muted">
              No devices registered yet.
            </div>
          ) : null}
        </div>
      ) : isLedger ? (
        <div className="grid grid-cols-1 gap-2">
          {data.items.map((item) => (
            <div
              key={typeof item === "string" ? item : item.label}
              className="rounded border border-line/35 bg-background/65 px-2 py-2 font-mono text-[11px] text-text"
            >
              <span className="mr-2 inline-block h-2 w-2 rounded-sm bg-cyan" />
              {typeof item === "string" ? item : item.label}
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {data.items.map((item) => (
            <div
              key={typeof item === "string" ? item : item.label}
              className="flex items-center gap-2 rounded border border-line/25 bg-background/55 px-2 py-1.5 font-mono text-[11px] text-muted"
            >
              <span className={`h-2 w-2 rounded-full ${bulletColor(item)}`} />
              {typeof item === "string" ? item : item.label}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function bulletColor(item: string | { label: string; color: string }): string {
  if (typeof item !== "string") return item.color;
  if (item.includes("Revocation") || item.includes("Accumulator")) return "bg-orange";
  if (item.includes("Audit")) return "bg-purple";
  if (item.includes("Fabric") || item.includes("Peer CLI") || item.includes("proof check")) {
    return "bg-cyan";
  }
  if (item.includes("VC verification") || item.includes("authorization") || item.includes("Decision")) {
    return "bg-green";
  }
  return "bg-blue";
}

function statusText(status: DashboardDevice["status"]): string {
  if (status === "active") return "text-green";
  if (status === "pending") return "text-purple";
  if (status === "revoked") return "text-danger";
  return "text-orange";
}

function shortDid(did: string): string {
  if (did.length <= 26) return did;
  return `${did.slice(0, 14)}...${did.slice(-8)}`;
}

function NodeHandles() {
  return (
    <>
      <Handle id="top" type="source" position={Position.Top} className="opacity-0" />
      <Handle id="right" type="source" position={Position.Right} className="opacity-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="opacity-0" />
      <Handle id="left" type="source" position={Position.Left} className="opacity-0" />
      <Handle id="top-target" type="target" position={Position.Top} className="opacity-0" />
      <Handle id="right-target" type="target" position={Position.Right} className="opacity-0" />
      <Handle id="bottom-target" type="target" position={Position.Bottom} className="opacity-0" />
      <Handle id="left-target" type="target" position={Position.Left} className="opacity-0" />
    </>
  );
}
