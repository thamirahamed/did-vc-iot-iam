import type { ServiceHealth } from "../types";

type StatusBarProps = {
  issuer: ServiceHealth;
  verifier: ServiceHealth;
  fabricAdapter: ServiceHealth;
};

export default function StatusBar({
  issuer,
  verifier,
  fabricAdapter,
}: StatusBarProps) {
  return (
    <header className="sticky top-0 z-30 flex min-h-16 items-center justify-between border-b border-line/30 bg-background/95 px-6 backdrop-blur">
      <div>
        <h2 className="text-lg font-semibold text-text">
          IoT Identity and Access Management Lab
        </h2>
        <p className="font-mono text-[11px] text-muted">
          Packet Tracer style DID, VC, revocation, audit, and Fabric telemetry
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-end gap-2">
        <HealthPill label="Issuer" health={issuer} />
        <HealthPill label="Verifier" health={verifier} />
        <HealthPill label="Fabric Adapter" health={fabricAdapter} />
        <HealthPill
          label="Fabric Network"
          health={{
            label: "Fabric Network",
            status: fabricAdapter.status,
            detail: fabricAdapter.status === "ok" ? "Connected" : "Unknown",
          }}
          onlineText="Connected"
        />
      </div>
    </header>
  );
}

function HealthPill({
  label,
  health,
  onlineText = "Online",
}: {
  label: string;
  health: ServiceHealth;
  onlineText?: string;
}) {
  const color =
    health.status === "ok"
      ? "bg-green text-green"
      : health.status === "unknown"
        ? "bg-orange text-orange"
        : "bg-danger text-danger";
  return (
    <div
      className="flex items-center gap-2 rounded border border-line/50 bg-panel px-3 py-1.5 font-mono text-[11px]"
      title={health.detail}
    >
      <span className={`h-2 w-2 rounded-full ${color.split(" ")[0]}`} />
      <span className="text-muted">{label}</span>
      <span className={color.split(" ")[1]}>
        {health.status === "ok" ? onlineText : "Unknown"}
      </span>
    </div>
  );
}
