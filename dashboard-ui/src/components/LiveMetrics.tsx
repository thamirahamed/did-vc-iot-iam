import { useEffect } from "react";
import { Activity } from "lucide-react";
import type { DemoSession } from "../types";

type LiveMetricsProps = {
  session: DemoSession;
};

export default function LiveMetrics({ session }: LiveMetricsProps) {
  const summary = session.ledgerSummary;
  // Accumulator version increments when accumulator membership or revocation state changes.
  // The root is the long hash and is intentionally not shown in Live Metrics.
  const versionMissing =
    !summary ||
    summary.accumulator_version === null ||
    summary.accumulator_version === undefined ||
    summary.accumulator_version === "" ||
    summary.accumulator_version === "unknown";
  const version = versionMissing ? "unknown" : summary.accumulator_version;
  const registeredDevices = summary?.registered_devices ?? session.devices.length;
  const activeCount = summary?.active_credentials ?? session.devices.filter(
    (device) => device.capabilityVc && !isCapabilityRevoked(device),
  ).length;
  const revokedCount = summary?.revoked_credentials ?? session.devices.filter(isCapabilityRevoked).length;

  useEffect(() => {
    if (import.meta.env.DEV && versionMissing) {
      console.warn("Accumulator version unavailable from dashboard summary");
    }
  }, [versionMissing]);

  const metrics = [
    { label: "Registered Devices", value: String(registeredDevices), color: "text-text" },
    { label: "Active Credentials", value: String(activeCount), color: "text-green" },
    { label: "Revoked Credentials", value: String(revokedCount), color: "text-danger" },
    { label: "Accumulator Version", value: String(version), color: "text-cyan", wide: true },
  ];

  return (
    <section className="glass-card flex h-full flex-col rounded p-4">
      <h3 className="mb-4 flex items-center gap-2 font-mono text-xs uppercase tracking-wide text-muted">
        <Activity size={16} /> Live Metrics
      </h3>
      <div className="grid flex-1 grid-cols-1 gap-3 md:grid-cols-3">
        {metrics.map((metric) => (
          <div
            key={metric.label}
            className={`flex min-h-20 flex-col justify-center rounded border border-line/30 bg-background/45 p-3 text-center ${
              metric.wide ? "md:col-span-3" : ""
            }`}
          >
            <div className={`break-all text-2xl font-bold [overflow-wrap:anywhere] ${metric.color}`}>
              {metric.value}
            </div>
            <div className="mt-1 font-mono text-[10px] uppercase text-muted">
              {metric.label}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function isCapabilityRevoked(device: DemoSession["devices"][number]): boolean {
  if (!device.capabilityVc) return false;
  if (device.status === "revoked" || device.capabilityStatus === "revoked") return true;
  const status = device.capabilityVc.credentialStatus;
  return Boolean(
    status &&
      typeof status === "object" &&
      "revoked" in status &&
      status.revoked === true,
  );
}
