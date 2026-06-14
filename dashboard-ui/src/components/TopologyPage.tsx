import {
  BadgePlus,
  Ban,
  Gauge,
  KeyRound,
  LockOpen,
  RefreshCw,
  ShieldPlus,
} from "lucide-react";
import type {
  ActionResult,
  AuditEvent,
  DemoSession,
} from "../types";
import AuditTimeline from "./AuditTimeline";
import LiveMetrics from "./LiveMetrics";
import TopologyCanvas from "./topology/TopologyCanvas";

type TopologyPageProps = {
  session: DemoSession;
  events: AuditEvent[];
  busyAction?: string;
  lastResult?: ActionResult;
  actionPending: boolean;
  selectedDeviceReady: boolean;
  onSelectDevice: (deviceId: string) => void;
  actions: {
    addDevice: () => void;
    issueIdentity: () => void;
    issueCapability: () => void;
    authorizeRead: () => void;
    revokeCapability: () => void;
    refreshProof: () => void;
    runBenchmark: () => void;
  };
};

export default function TopologyPage({
  session,
  events,
  busyAction,
  lastResult,
  actionPending,
  selectedDeviceReady,
  onSelectDevice,
  actions,
}: TopologyPageProps) {
  const buttons = [
    { id: "add-device", label: "Add Device", loading: "Creating...", icon: BadgePlus, onClick: actions.addDevice },
    {
      id: "identity",
      label: "Issue Identity VC",
      loading: "Issuing...",
      icon: ShieldPlus,
      onClick: actions.issueIdentity,
      tone: "text-blue",
      needsDevice: true,
    },
    {
      id: "capability",
      label: "Issue Capability VC",
      loading: "Issuing...",
      icon: KeyRound,
      onClick: actions.issueCapability,
      tone: "text-blue",
      needsDevice: true,
    },
    {
      id: "authorize",
      label: "Authorize Request",
      loading: "Authorizing...",
      icon: LockOpen,
      onClick: actions.authorizeRead,
      tone: "text-green",
      needsDevice: true,
    },
    {
      id: "revoke",
      label: "Revoke Credential",
      loading: "Revoking...",
      icon: Ban,
      onClick: actions.revokeCapability,
      tone: "text-danger",
      needsDevice: true,
    },
    {
      id: "refresh",
      label: "Refresh Proof",
      loading: "Refreshing...",
      icon: RefreshCw,
      onClick: actions.refreshProof,
      tone: "text-cyan",
      needsDevice: true,
    },
    {
      id: "benchmark",
      label: "Run Benchmark",
      loading: "Opening...",
      icon: Gauge,
      onClick: actions.runBenchmark,
      tone: "text-purple",
    },
  ];

  return (
    <div className="w-full">
      <TopologyCanvas
        devices={session.devices}
        selectedDeviceId={session.selectedDeviceId}
        onSelectDevice={onSelectDevice}
      />
      <div className="flex w-full flex-wrap items-center justify-center gap-2 border-b border-line/30 bg-panel/80 p-3">
        {buttons.map((button) => {
          const Icon = button.icon;
          const busy = busyAction === button.id;
          const disabled = actionPending || Boolean(button.needsDevice && !selectedDeviceReady);
          return (
            <button
              key={button.id}
              type="button"
              onClick={button.onClick}
              disabled={disabled}
              title={button.needsDevice && !selectedDeviceReady ? "Select a device first." : undefined}
              className="flex items-center gap-2 rounded border border-line/45 bg-panel-strong px-3 py-2 font-mono text-xs text-text transition hover:border-cyan/50 hover:bg-panel disabled:cursor-wait disabled:opacity-60"
            >
              <Icon size={15} className={button.tone || "text-cyan"} />
              {busy ? button.loading : button.label}
            </button>
          );
        })}
        {!selectedDeviceReady ? (
          <span className="font-mono text-[11px] text-orange">Select a device first.</span>
        ) : null}
      </div>
      {lastResult ? (
        <div
          className={`mx-6 mt-4 rounded border px-4 py-3 text-sm ${
            lastResult.ok
              ? "border-green/35 bg-green/10 text-green"
              : "border-orange/35 bg-orange/10 text-orange"
          }`}
        >
          <span className="font-semibold">{lastResult.title}: </span>
          {lastResult.message}
        </div>
      ) : null}
      <div className="grid gap-4 p-6 xl:grid-cols-[0.85fr_2.15fr]">
        <LiveMetrics session={session} />
        <AuditTimeline events={events} demoData={session.demoData} />
      </div>
    </div>
  );
}
