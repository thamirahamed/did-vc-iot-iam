import {
  Ban,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Signature,
} from "lucide-react";
import type {
  ActionResult,
  DashboardDevice,
  ScenarioResultsPage,
} from "../types";

type ScenarioId =
  | "happy-path"
  | "wrong-action"
  | "bad-signature"
  | "revocation"
  | "proof-refresh";

type SecurityScenariosPageProps = {
  devices: DashboardDevice[];
  selectedDeviceId?: string;
  runningScenarioId?: string;
  lastResult?: ActionResult;
  scenarioResults: ScenarioResultsPage;
  onSelectDevice: (deviceId: string) => void;
  onRunScenario: (scenarioId: ScenarioId) => void;
  onResultsPageChange: (page: number) => void;
};

const scenarios: Array<{
  id: ScenarioId;
  title: string;
  icon: typeof ShieldCheck;
  body: string;
  expected: "allow" | "deny";
}> = [
  {
    id: "happy-path",
    title: "Happy Path",
    icon: ShieldCheck,
    body: "Authorize a normal read request with active identity, capability, and accumulator proofs.",
    expected: "allow",
  },
  {
    id: "wrong-action",
    title: "Wrong Action Attack",
    icon: Ban,
    body: "Present a read capability but request write access. The verifier should deny.",
    expected: "deny",
  },
  {
    id: "bad-signature",
    title: "Bad Signature Attack",
    icon: Signature,
    body: "Tamper the device nonce signature before calling verifier authorization.",
    expected: "deny",
  },
  {
    id: "revocation",
    title: "Revocation Scenario",
    icon: ShieldAlert,
    body: "Revoke the selected capability VC and test authorization with stale proof evidence.",
    expected: "deny",
  },
  {
    id: "proof-refresh",
    title: "Proof Refresh Scenario",
    icon: RefreshCw,
    body: "Refresh active accumulator proofs, then authorize a read request.",
    expected: "allow",
  },
];

export default function SecurityScenariosPage({
  devices,
  selectedDeviceId,
  runningScenarioId,
  lastResult,
  scenarioResults,
  onSelectDevice,
  onRunScenario,
  onResultsPageChange,
}: SecurityScenariosPageProps) {
  const selectedDevice = devices.find((device) => device.id === selectedDeviceId);
  const globalDisabledReason = selectedDevice
    ? selectedDevice.status === "revoked"
      ? "Restore access before running active credential scenarios."
      : ""
    : "Select a device to run scenarios.";

  return (
    <div className="space-y-5 p-6">
      <section className="glass-card rounded p-5">
        <h2 className="text-xl font-semibold">Security Scenarios</h2>
        <p className="mt-1 text-sm text-muted">
          Run verifier-facing DID, VC, signature, revocation, and accumulator checks.
        </p>
      </section>

      <section className="glass-card rounded p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold">Scenario Device</h3>
            <p className="mt-1 text-sm text-muted">
              {selectedDevice
                ? `Selected device: ${selectedDevice.label}`
                : "Select a device to run scenarios."}
            </p>
          </div>
        </div>
        {devices.length ? (
          <div className="flex flex-wrap gap-2">
            {devices.map((device) => (
              <button
                key={device.id}
                type="button"
                onClick={() => onSelectDevice(device.id)}
                className={`rounded border px-3 py-2 text-left text-xs transition ${
                  selectedDeviceId === device.id
                    ? "border-cyan/55 bg-cyan/10 text-cyan"
                    : "border-line/45 bg-panel text-text hover:border-cyan/40"
                }`}
              >
                <span className="flex items-center gap-2">
                  <span
                    className={`h-2 w-2 rounded-full ${
                      device.status === "active"
                        ? "bg-green"
                        : device.status === "revoked"
                          ? "bg-danger"
                          : "bg-orange"
                    }`}
                  />
                  <span className="font-semibold">{device.label}</span>
                  <span className="font-mono text-muted">{device.status}</span>
                </span>
              </button>
            ))}
          </div>
        ) : (
          <div className="rounded border border-line/35 bg-background/45 p-4 text-muted">
            No devices available.
          </div>
        )}
        {globalDisabledReason ? (
          <div className="mt-3 rounded border border-orange/35 bg-orange/10 px-3 py-2 text-sm text-orange">
            {globalDisabledReason}
          </div>
        ) : null}
      </section>

      {lastResult ? (
        <div
          className={`rounded border p-4 text-sm ${
            lastResult.ok
              ? "border-green/35 bg-green/10 text-green"
              : "border-orange/35 bg-orange/10 text-orange"
          }`}
        >
          <span className="font-semibold">{lastResult.title}: </span>
          {lastResult.message}
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
        {scenarios.map((scenario) => {
          const Icon = scenario.icon;
          const running = runningScenarioId === scenario.id;
          const disabledReason = scenarioDisabledReason(scenario.id, selectedDevice);
          const disabled = Boolean(runningScenarioId || disabledReason);
          return (
            <section key={scenario.id} className="glass-card rounded p-5">
              <div className="mb-3 flex items-center gap-3">
                <Icon className="text-cyan" size={22} />
                <h3 className="text-lg font-semibold">{scenario.title}</h3>
              </div>
              <p className="min-h-16 text-sm leading-6 text-muted">{scenario.body}</p>
              <div className="mt-3 font-mono text-[11px] uppercase text-muted">
                Expected <StatusText value={scenario.expected} />
              </div>
              {disabledReason ? (
                <p className="mt-3 min-h-10 text-xs leading-5 text-orange">{disabledReason}</p>
              ) : (
                <div className="mt-3 min-h-10" />
              )}
              <button
                type="button"
                onClick={() => onRunScenario(scenario.id)}
                disabled={disabled}
                className="mt-2 rounded border border-line/45 bg-panel-strong px-3 py-2 font-mono text-xs text-text transition hover:border-cyan/50 disabled:cursor-wait disabled:opacity-60"
              >
                {running ? "Running" : "Run Scenario"}
              </button>
            </section>
          );
        })}
      </div>

      <ScenarioResultsTable
        page={scenarioResults.page}
        totalPages={scenarioResults.total_pages}
        totalRows={scenarioResults.total}
        rows={scenarioResults.items}
        onPageChange={onResultsPageChange}
      />
    </div>
  );
}

function ScenarioResultsTable({
  rows,
  page,
  totalPages,
  totalRows,
  onPageChange,
}: {
  rows: ScenarioResultsPage["items"];
  page: number;
  totalPages: number;
  totalRows: number;
  onPageChange: (page: number) => void;
}) {
  return (
    <section className="glass-card rounded p-5">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-lg font-semibold">Scenario Results</h3>
        {totalRows > 10 ? (
          <div className="flex items-center gap-2 font-mono text-xs text-muted">
            <button
              type="button"
              onClick={() => onPageChange(Math.max(1, page - 1))}
              disabled={page <= 1}
              className="rounded border border-line/40 bg-panel px-3 py-1 text-text disabled:cursor-not-allowed disabled:opacity-40"
            >
              Previous
            </button>
            <span>Page {page} of {totalPages}</span>
            <button
              type="button"
              onClick={() => onPageChange(Math.min(totalPages, page + 1))}
              disabled={page >= totalPages}
              className="rounded border border-line/40 bg-panel px-3 py-1 text-text disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next
            </button>
          </div>
        ) : null}
      </div>
      {rows.length ? (
        <div className="overflow-x-auto rounded border border-line/30 bg-background/45">
          <table className="ledger-table w-full min-w-[960px] text-left text-xs">
            <thead className="font-mono uppercase">
              <tr>
                <HeaderCell>Time</HeaderCell>
                <HeaderCell>Scenario</HeaderCell>
                <HeaderCell>Device</HeaderCell>
                <HeaderCell>Expected</HeaderCell>
                <HeaderCell>Actual</HeaderCell>
                <HeaderCell>Reason</HeaderCell>
                <HeaderCell>Status</HeaderCell>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id || `${row.time}:${row.scenario}`} className="border-b border-line/20 last:border-0">
                  <BodyCell>{formatIstDateTime(row.time)}</BodyCell>
                  <BodyCell>{row.scenario}</BodyCell>
                  <BodyCell>{row.device}</BodyCell>
                  <BodyCell><StatusText value={row.expected} /></BodyCell>
                  <BodyCell><StatusText value={row.actual} /></BodyCell>
                  <BodyCell>{row.reason || "Not available"}</BodyCell>
                  <BodyCell><StatusText value={row.status} /></BodyCell>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="rounded border border-line/35 bg-background/45 p-4 text-muted">
          No scenario results yet.
        </div>
      )}
    </section>
  );
}

function HeaderCell({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2 text-[10px] font-semibold">{children}</th>;
}

function BodyCell({ children }: { children: React.ReactNode }) {
  return <td className="px-3 py-2 align-top text-text">{children}</td>;
}

function StatusText({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const color =
    normalized === "pass" || normalized === "allow"
      ? "text-green"
      : normalized === "fail" || normalized === "deny"
        ? "text-danger"
        : normalized === "error"
          ? "text-orange"
          : "text-muted";
  return <span className={`font-mono ${color}`}>{value || "unknown"}</span>;
}

function scenarioDisabledReason(
  scenarioId: ScenarioId,
  device: DashboardDevice | undefined,
): string {
  if (!device) return "Select a device to run scenarios.";
  if (device.status === "revoked") return "Restore access before running active credential scenarios.";
  if (device.status !== "active") return "Selected device is not active.";
  if (!device.identityVc) return "Identity VC is required.";
  if (!device.capabilityVc) return "Capability VC is required.";
  if (scenarioId === "revocation" && device.capabilityStatus !== "active") {
    return "Active capability VC is required.";
  }
  if (["happy-path", "proof-refresh"].includes(scenarioId) && !device.identityProof) {
    return "Identity proof is required.";
  }
  if (!device.capabilityProof) return "Capability proof is required.";
  return "";
}

function formatIstDateTime(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not available";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return "Not available";
  return new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}
