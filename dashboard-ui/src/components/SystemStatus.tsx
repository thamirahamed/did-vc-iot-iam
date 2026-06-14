import { ServerCog } from "lucide-react";
import type { ServiceHealth } from "../types";

type SystemStatusProps = {
  issuer: ServiceHealth;
  verifier: ServiceHealth;
  fabricAdapter: ServiceHealth;
};

export default function SystemStatus({
  issuer,
  verifier,
  fabricAdapter,
}: SystemStatusProps) {
  return (
    <section className="glass-card flex h-full flex-col rounded p-4">
      <h3 className="mb-4 flex items-center gap-2 font-mono text-xs uppercase tracking-wide text-muted">
        <ServerCog size={16} /> System Status
      </h3>
      <div className="space-y-3 text-sm">
        <StatusRow label="Issuer Health" value={issuer.detail || issuer.status} health={issuer.status} />
        <StatusRow label="Verifier Health" value={verifier.detail || verifier.status} health={verifier.status} />
        <StatusRow label="Fabric Adapter Health" value={fabricAdapter.detail || fabricAdapter.status} health={fabricAdapter.status} />
        <StatusRow label="Revocation Mode" value="Accumulator" accent="text-cyan" />
        <StatusRow label="Audit Mode" value="Async" accent="text-purple" />
        <StatusRow label="Fabric Client" value="Adapter" accent="text-cyan" />
        <StatusRow
          label="Fabric Network"
          value={fabricAdapter.status === "ok" ? "Connected" : "Unknown"}
          accent={fabricAdapter.status === "ok" ? "text-green" : "text-orange"}
        />
      </div>
    </section>
  );
}

function StatusRow({
  label,
  value,
  health,
  accent,
}: {
  label: string;
  value: string;
  health?: ServiceHealth["status"];
  accent?: string;
}) {
  const color =
    accent ||
    (health === "ok"
      ? "text-green"
      : health === "unknown"
        ? "text-orange"
        : "text-danger");
  return (
    <div className="flex items-center justify-between gap-4 border-b border-line/30 pb-2 last:border-b-0">
      <span className="text-muted">{label}</span>
      <span className={`max-w-[55%] truncate text-right font-mono text-xs ${color}`}>
        {value}
      </span>
    </div>
  );
}
