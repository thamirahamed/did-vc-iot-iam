import {
  BadgePlus,
  Ban,
  KeyRound,
  LockOpen,
  RefreshCw,
  ShieldPlus,
  Undo2,
  Wallet,
} from "lucide-react";
import type { DashboardDevice, DemoSession, DeviceAuditEventsPage } from "../types";

type DeviceWalletPageProps = {
  session: DemoSession;
  busyAction?: string;
  actionPending: boolean;
  selectedDeviceReady: boolean;
  selectedDeviceSelectable: boolean;
  timeline: DeviceAuditEventsPage;
  onSelectDevice: (deviceId: string) => void;
  onTimelinePageChange: (page: number) => void;
  actions: {
    addDevice: () => void;
    issueIdentity: () => void;
    issueCapability: () => void;
    refreshProof: () => void;
    authorizeRead: () => void;
    restoreAccess: () => void;
    revokeCapability: () => void;
  };
};

export default function DeviceWalletPage({
  session,
  busyAction,
  actionPending,
  selectedDeviceReady,
  selectedDeviceSelectable,
  timeline,
  onSelectDevice,
  onTimelinePageChange,
  actions,
}: DeviceWalletPageProps) {
  const selectedDevice = session.devices.find(
    (device) => device.id === session.selectedDeviceId,
  );

  const helperText = walletHelperText(selectedDevice, selectedDeviceSelectable);
  const buttons = walletButtons({
    selectedDevice,
    selectedDeviceReady,
    selectedDeviceSelectable,
    actionPending,
    busyAction,
    actions,
  });

  if (!selectedDevice) {
    return (
      <div className="space-y-5 p-6">
        <DeviceList
          devices={session.devices}
          selectedDeviceId={session.selectedDeviceId}
          onSelectDevice={onSelectDevice}
        />
        <WalletActions buttons={buttons} helperText={helperText} />
      <section className="glass-card rounded p-8 text-center">
          <Wallet className="mx-auto text-cyan" size={28} />
          <h2 className="mt-3 text-xl font-semibold">Device Wallet</h2>
          <p className="mt-2 text-muted">
            {session.devices.length
              ? "Select or add a device to view wallet details."
              : "No devices registered yet. Add a device from this page."}
          </p>
        </section>
        <DeviceEventTimeline timeline={timeline} onPageChange={onTimelinePageChange} />
      </div>
    );
  }

  const identityId = selectedDevice.identityVc?.id || "Not issued";
  const capabilityId = selectedDevice.capabilityVc?.id || "Not issued";
  const proofVersion =
    selectedDevice.capabilityProof?.version ?? selectedDevice.identityProof?.version ?? "None";
  const root =
    selectedDevice.capabilityProof?.root || selectedDevice.identityProof?.root || "";

  return (
    <div className="space-y-5 p-6">
      <DeviceList
        devices={session.devices}
        selectedDeviceId={session.selectedDeviceId}
        onSelectDevice={onSelectDevice}
      />
      <WalletActions buttons={buttons} helperText={helperText} />
      <section className="glass-card rounded p-5">
        <div className="mb-4 flex items-center gap-3">
          <Wallet className="text-cyan" size={22} />
          <div>
            <h2 className="text-xl font-semibold">Device Wallet</h2>
            <p className="font-mono text-xs text-muted">{selectedDevice.label}</p>
          </div>
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <WalletField label="DID" value={selectedDevice.did || "DID pending"} />
          <WalletField
            label="Public Key Prefix"
            value={selectedDevice.publicKeyPrefix || "Not generated"}
          />
          <WalletField label="Identity VC ID" value={identityId} />
          <WalletField label="Capability VC ID" value={capabilityId} />
          <WalletField label="Credential Status" value={selectedDevice.capabilityStatus || selectedDevice.status} />
          <WalletField label="Latest Decision" value={selectedDevice.latestDecision || "None"} />
        </div>
      </section>
      <div className="grid gap-5 xl:grid-cols-2">
        <CredentialCard title="Identity VC" id={identityId} data={selectedDevice.identityVc} />
        <CredentialCard title="Capability VC" id={capabilityId} data={selectedDevice.capabilityVc} />
      </div>
      <section className="glass-card rounded p-5">
        <h3 className="mb-4 font-mono text-xs uppercase text-muted">Accumulator Proof</h3>
        <div className="grid gap-4 lg:grid-cols-3">
          <WalletField label="Proof Version" value={String(proofVersion)} />
          <WalletField label="Root Prefix" value={root ? `${root.slice(0, 12)}...` : "unavailable"} />
          <WalletField
            label="Proof Status"
            value={selectedDevice.capabilityProof || selectedDevice.identityProof ? "Available" : "Missing"}
          />
        </div>
      </section>
      <DeviceEventTimeline timeline={timeline} onPageChange={onTimelinePageChange} />
    </div>
  );
}

type WalletButtonConfig = {
  id: string;
  label: string;
  loading: string;
  icon: typeof ShieldPlus;
  tone: string;
  busy: boolean;
  disabled: boolean;
  title?: string;
  onClick: () => void;
};

function walletButtons({
  selectedDevice,
  selectedDeviceReady,
  selectedDeviceSelectable,
  actionPending,
  busyAction,
  actions,
}: {
  selectedDevice?: DashboardDevice;
  selectedDeviceReady: boolean;
  selectedDeviceSelectable: boolean;
  actionPending: boolean;
  busyAction?: string;
  actions: DeviceWalletPageProps["actions"];
}): WalletButtonConfig[] {
  const hasIdentityVc = Boolean(selectedDevice?.identityVc);
  const hasIdentityProof = Boolean(selectedDevice?.identityProof);
  const hasCapabilityVc = Boolean(selectedDevice?.capabilityVc);
  const hasAccumulatorProof = hasIdentityProof || Boolean(selectedDevice?.capabilityProof);
  const hasActiveCapability =
    hasCapabilityVc &&
    selectedDevice?.status === "active" &&
    selectedDevice.capabilityStatus !== "revoked";
  const canCheckAccess = hasActiveCapability && hasAccumulatorProof;
  const isRevoked = selectedDevice?.status === "revoked";
  const duplicateTitle =
    selectedDeviceReady && hasIdentityVc && hasCapabilityVc
      ? "Device already has active credentials."
      : undefined;
  const capabilityTitle = !selectedDeviceSelectable
    ? "Select a device first."
    : !hasIdentityVc
      ? "Issue Identity VC first."
      : !hasIdentityProof
        ? "Identity VC needs accumulator proof. Reissue identity after reset."
        : duplicateTitle;

  return [
    {
      id: "add-device",
      label: "Add Device",
      loading: "Creating...",
      icon: BadgePlus,
      tone: "text-cyan",
      disabled: actionPending,
      onClick: actions.addDevice,
    },
    {
      id: "identity",
      label: "Issue Identity VC",
      loading: "Issuing...",
      icon: ShieldPlus,
      tone: "text-blue",
      disabled: actionPending || !selectedDeviceReady || hasIdentityVc || isRevoked,
      title: !selectedDeviceSelectable
        ? "Select a device first."
        : hasIdentityVc
          ? duplicateTitle || "Identity VC already issued."
          : undefined,
      onClick: actions.issueIdentity,
    },
    {
      id: "capability",
      label: "Issue Capability VC",
      loading: "Issuing...",
      icon: KeyRound,
      tone: "text-blue",
      disabled:
        actionPending ||
        !selectedDeviceReady ||
        isRevoked ||
        !hasIdentityVc ||
        !hasIdentityProof ||
        hasCapabilityVc,
      title: capabilityTitle,
      onClick: actions.issueCapability,
    },
    {
      id: "refresh",
      label: "Refresh Proof",
      loading: "Refreshing...",
      icon: RefreshCw,
      tone: "text-orange",
      disabled: actionPending || !selectedDeviceReady || isRevoked || !hasIdentityProof,
      title: !selectedDeviceSelectable ? "Select a device first." : undefined,
      onClick: actions.refreshProof,
    },
    {
      id: "authorize",
      label: "Check Access",
      loading: "Checking...",
      icon: LockOpen,
      tone: "text-green",
      disabled: actionPending || !selectedDeviceReady || !canCheckAccess,
      title: !selectedDeviceSelectable ? "Select a device first." : undefined,
      onClick: actions.authorizeRead,
    },
    {
      id: "restore",
      label: "Restore Access",
      loading: "Restoring...",
      icon: Undo2,
      tone: "text-green",
      disabled: actionPending || !selectedDeviceSelectable || !isRevoked,
      title: !selectedDeviceSelectable ? "Select a device first." : undefined,
      onClick: actions.restoreAccess,
    },
    {
      id: "revoke",
      label: "Revoke Capability VC",
      loading: "Revoking...",
      icon: Ban,
      tone: "text-danger",
      disabled: actionPending || !selectedDeviceReady || !hasActiveCapability,
      title: !selectedDeviceSelectable ? "Select a device first." : undefined,
      onClick: actions.revokeCapability,
    },
  ].map((button) => ({
    ...button,
    busy: busyAction === button.id,
    disabled: button.disabled || (Boolean(busyAction) && busyAction !== button.id),
  }));
}

function walletHelperText(
  selectedDevice: DashboardDevice | undefined,
  selectedDeviceSelectable: boolean,
): string | undefined {
  if (!selectedDeviceSelectable) return "Select a device first.";
  if (!selectedDevice) return "Select a device first.";
  if (selectedDevice.status === "revoked") return "Restore Access is available for this revoked device.";
  if (selectedDevice.identityVc && selectedDevice.capabilityVc) {
    return "Device already has active credentials.";
  }
  if (!selectedDevice.identityVc) return undefined;
  if (!selectedDevice.identityProof) {
    return "Identity VC needs accumulator proof. Reissue identity after reset.";
  }
  return undefined;
}

function WalletActions({
  buttons,
  helperText,
}: {
  buttons: WalletButtonConfig[];
  helperText?: string;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      {buttons.map((button) => (
        <WalletButton
          key={button.id}
          label={button.label}
          loading={button.loading}
          icon={button.icon}
          tone={button.tone}
          busy={button.busy}
          disabled={button.disabled}
          title={button.title}
          onClick={button.onClick}
        />
      ))}
      {helperText ? (
        <span className="self-center font-mono text-[11px] text-orange">{helperText}</span>
      ) : null}
    </div>
  );
}

function DeviceList({
  devices,
  selectedDeviceId,
  onSelectDevice,
}: {
  devices: DashboardDevice[];
  selectedDeviceId?: string;
  onSelectDevice: (deviceId: string) => void;
}) {
  return (
    <section className="glass-card rounded p-4">
      <h3 className="mb-3 font-mono text-xs uppercase text-muted">Registered Devices</h3>
      <div className="flex flex-wrap gap-2">
        {devices.map((device) => (
          <button
            key={device.id}
            type="button"
            onClick={() => onSelectDevice(device.id)}
            className={`rounded border px-3 py-2 text-left font-mono text-xs ${
              selectedDeviceId === device.id
                ? "border-cyan/60 bg-cyan/10 text-cyan"
                : "border-line/40 bg-panel-strong text-muted hover:text-text"
            }`}
          >
            <span className="flex items-center gap-2">
              <StatusDot status={device.status} />
              <span>{device.label}</span>
              <span className="text-[10px] uppercase text-muted">{device.status || "unknown"}</span>
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}

function StatusDot({ status }: { status?: DashboardDevice["status"] }) {
  const dotClass =
    status === "active"
      ? "bg-green"
      : status === "revoked"
        ? "bg-danger"
        : "bg-muted";
  return <span className={`h-2.5 w-2.5 rounded-full ${dotClass}`} aria-hidden="true" />;
}

function WalletField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-line/30 bg-background/45 p-3">
      <div className="font-mono text-[10px] uppercase text-muted">{label}</div>
      <div className="mt-2 truncate font-mono text-xs text-text" title={value}>
        {value}
      </div>
    </div>
  );
}

function CredentialCard({
  title,
  id,
  data,
}: {
  title: string;
  id: string;
  data?: Record<string, unknown>;
}) {
  return (
    <section className="glass-card rounded p-5">
      <h3 className="mb-3 text-lg font-semibold">{title}</h3>
      <WalletField label="Credential ID" value={id} />
      <pre className="mt-4 max-h-72 overflow-auto rounded border border-line/30 bg-background/70 p-3 font-mono text-[11px] leading-5 text-muted">
        {data ? JSON.stringify(data, null, 2) : "Credential not issued yet."}
      </pre>
    </section>
  );
}

function WalletButton({
  label,
  loading,
  icon: Icon,
  tone,
  busy,
  disabled,
  title,
  onClick,
}: {
  label: string;
  loading: string;
  icon: typeof ShieldPlus;
  tone: string;
  busy: boolean;
  disabled: boolean;
  title?: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="flex items-center gap-2 rounded border border-line/45 bg-panel-strong px-3 py-2 font-mono text-xs text-text transition hover:border-cyan/50 hover:bg-panel disabled:cursor-wait disabled:opacity-60"
    >
      <Icon size={15} className={tone} />
      {busy ? loading : label}
    </button>
  );
}

function DeviceEventTimeline({
  timeline,
  onPageChange,
}: {
  timeline: DeviceAuditEventsPage;
  onPageChange: (page: number) => void;
}) {
  const page = timeline.page || 1;
  const totalPages = timeline.total_pages || 1;
  return (
    <section className="glass-card overflow-hidden rounded">
      <div className="flex items-center justify-between border-b border-line/30 p-4">
        <h3 className="font-mono text-xs uppercase tracking-wide text-muted">
          Device Event Timeline
        </h3>
        <span className="font-mono text-[10px] uppercase text-muted">
          {timeline.total} events
        </span>
      </div>
      <div className="overflow-auto">
        <table className="w-full min-w-[680px] text-left text-sm">
          <thead className="sticky top-0 bg-panel">
            <tr className="border-b border-line/30 font-mono text-[10px] uppercase text-muted">
              <th className="px-4 py-3">Event</th>
              <th className="px-4 py-3">Service</th>
              <th className="px-4 py-3">Device</th>
              <th className="px-4 py-3">Subject / Credential</th>
              <th className="px-4 py-3">Result</th>
            </tr>
          </thead>
          <tbody>
            {timeline.items.map((event, index) => (
              <tr
                key={`${event.created_at || "event"}-${event.event}-${index}`}
                className="border-b border-line/20 last:border-b-0"
              >
                <td className="px-4 py-3 font-mono text-xs text-cyan">{event.event}</td>
                <td className="px-4 py-3 text-muted">{event.service}</td>
                <td className="px-4 py-3 text-muted">{event.device}</td>
                <td className="max-w-[260px] truncate px-4 py-3 font-mono text-xs">
                  {event.subject_or_credential}
                </td>
                <td className="px-4 py-3">
                  <span className={event.result === "deny" ? "text-danger" : "text-green"}>
                    {event.result}
                  </span>
                </td>
              </tr>
            ))}
            {!timeline.items.length ? (
              <tr>
                <td className="px-4 py-6 text-muted" colSpan={5}>
                  No events for this device yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-end gap-3 border-t border-line/30 p-3">
        <button
          type="button"
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page <= 1}
          className="rounded border border-line/45 bg-panel-strong px-3 py-2 font-mono text-xs text-text transition hover:border-cyan/50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Previous
        </button>
        <span className="font-mono text-xs text-muted">
          Page {page} of {totalPages}
        </span>
        <button
          type="button"
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          disabled={page >= totalPages}
          className="rounded border border-line/45 bg-panel-strong px-3 py-2 font-mono text-xs text-text transition hover:border-cyan/50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Next
        </button>
      </div>
    </section>
  );
}
