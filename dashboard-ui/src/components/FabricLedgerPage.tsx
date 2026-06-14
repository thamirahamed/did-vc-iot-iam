import { useCallback, useEffect, useMemo, useState } from "react";
import { Database, RefreshCw } from "lucide-react";
import {
  errorMessage,
  getAuditEvents,
  getAccumulatorState,
  getDashboardDevices,
  getLedgerSummary,
  type LedgerSummary,
} from "../api/client";
import type {
  AccumulatorProof,
  AccumulatorState,
  AuditEvent,
  DashboardDevice,
  VerifiableCredential,
} from "../types";

const tabs = ["DID Registry", "Credential Status", "Accumulator State", "Audit Events"] as const;
const tablePageSize = 15;

type DidRow = {
  device: string;
  did: string;
  publicKeyPrefix: string;
  status: string;
  registeredAt: string;
  issuer: string;
};

type CredentialRow = {
  credentialId: string;
  type: string;
  device: string;
  subject: string;
  status: string;
  accumulatorVersion: string;
  updatedAt: string;
};

type AuditRow = {
  time: string;
  event: string;
  service: string;
  device: string;
  subject: string;
  credentialId: string;
  credentialType: string;
  result: string;
  reason: string;
};

type PaginatedTableProps<T> = {
  rows: T[];
  page: number;
  totalPages: number;
  totalRows: number;
  onPageChange: (page: number) => void;
};

export default function FabricLedgerPage() {
  const [activeTab, setActiveTab] = useState<(typeof tabs)[number]>("DID Registry");
  const [devices, setDevices] = useState<DashboardDevice[]>([]);
  const [state, setState] = useState<AccumulatorState | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [auditTotalRows, setAuditTotalRows] = useState(0);
  const [auditTotalPages, setAuditTotalPages] = useState(1);
  const [summary, setSummary] = useState<LedgerSummary | null>(null);
  const [error, setError] = useState<string>("");
  const [refreshing, setRefreshing] = useState(false);
  const [didPage, setDidPage] = useState(1);
  const [credentialPage, setCredentialPage] = useState(1);
  const [auditPage, setAuditPage] = useState(1);

  const loadLedgerData = useCallback(async (options?: { mounted?: () => boolean }) => {
    setRefreshing(true);
    try {
      const [deviceResult, stateResult, eventResult, summaryResult] = await Promise.all([
        getDashboardDevices(),
        getAccumulatorState(),
        getAuditEvents(auditPage, tablePageSize),
        getLedgerSummary(),
      ]);
      if (options?.mounted && !options.mounted()) return;
      setDevices(deviceResult);
      setState(stateResult);
      setEvents(eventResult.items);
      setAuditTotalRows(eventResult.total);
      setAuditTotalPages(eventResult.total_pages);
      setSummary(summaryResult);
      setError("");
    } catch (err) {
      if (!options?.mounted || options.mounted()) {
        setError(errorMessage(err));
      }
    } finally {
      if (!options?.mounted || options.mounted()) {
        setRefreshing(false);
      }
    }
  }, [auditPage]);

  useEffect(() => {
    let mounted = true;
    loadLedgerData({ mounted: () => mounted });
    return () => {
      mounted = false;
    };
  }, [loadLedgerData]);

  const didRows = useMemo(() => devices.filter((device) => device.did).map(toDidRow), [devices]);
  const credentialRows = useMemo(() => devices.flatMap(toCredentialRows), [devices]);
  const auditRows = useMemo(() => toAuditRows(events, devices), [events, devices]);
  const totalDidPages = pageCount(didRows.length);
  const totalCredentialPages = pageCount(credentialRows.length);
  const visibleDidRows = pageRows(didRows, didPage);
  const visibleCredentialRows = pageRows(credentialRows, credentialPage);

  useEffect(() => {
    setDidPage((page) => Math.min(page, totalDidPages));
  }, [totalDidPages]);

  useEffect(() => {
    setCredentialPage((page) => Math.min(page, totalCredentialPages));
  }, [totalCredentialPages]);

  useEffect(() => {
    setAuditPage((page) => Math.min(page, auditTotalPages));
  }, [auditTotalPages]);

  useEffect(() => {
    if (activeTab === "DID Registry") setDidPage(1);
    if (activeTab === "Credential Status") setCredentialPage(1);
    if (activeTab === "Audit Events") setAuditPage(1);
  }, [activeTab]);

  return (
    <div className="space-y-5 p-6">
      <section className="glass-card rounded p-5">
        <div className="flex items-center gap-3">
          <Database className="text-cyan" />
          <div>
            <h2 className="text-xl font-semibold">Fabric Ledger Explorer</h2>
            <p className="font-mono text-xs text-muted">
              Hyperledger Fabric IAM Ledger / IAM Chaincode
            </p>
          </div>
        </div>
      </section>
      <div className="ledger-tab-toolbar">
        <div className="ledger-tabs">
          {tabs.map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`rounded border px-3 py-2 font-mono text-xs ${
                activeTab === tab
                  ? "border-cyan/45 bg-cyan/10 text-cyan"
                  : "border-line/40 bg-panel text-muted hover:text-text"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => loadLedgerData()}
          disabled={refreshing}
          className="ledger-refresh-button"
        >
          <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} />
          {refreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>
      {error ? (
        <div className="rounded border border-orange/40 bg-orange/10 px-3 py-2 text-sm text-orange">
          Refresh failed: {error}
        </div>
      ) : null}
      <section className="glass-card rounded p-5">
        {summary ? (
          <div className="mb-5 grid gap-3 md:grid-cols-4">
            <SummaryTile label="Devices" value={summary.registered_devices} />
            <SummaryTile label="Active Credentials" value={summary.active_credentials} />
            <SummaryTile label="Revoked Credentials" value={summary.revoked_credentials} />
            <SummaryTile label="Accumulator Version" value={summary.accumulator_version ?? 0} />
          </div>
        ) : null}
        {activeTab === "DID Registry" ? (
          <DidRegistryTable
            rows={visibleDidRows}
            page={didPage}
            totalPages={totalDidPages}
            totalRows={didRows.length}
            onPageChange={setDidPage}
          />
        ) : null}
        {activeTab === "Credential Status" ? (
          <CredentialStatusTable
            rows={visibleCredentialRows}
            page={credentialPage}
            totalPages={totalCredentialPages}
            totalRows={credentialRows.length}
            onPageChange={setCredentialPage}
          />
        ) : null}
        {activeTab === "Accumulator State" ? <AccumulatorStatePanel state={state} /> : null}
        {activeTab === "Audit Events" ? (
          <AuditEventsTable
            rows={auditRows}
            page={auditPage}
            totalPages={auditTotalPages}
            totalRows={auditTotalRows}
            onPageChange={setAuditPage}
          />
        ) : null}
      </section>
    </div>
  );
}

function SummaryTile({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="rounded border border-line/30 bg-background/45 p-3 text-center">
      <div className="break-all text-xl font-semibold text-cyan">{String(value)}</div>
      <div className="mt-1 font-mono text-[10px] uppercase text-muted">{label}</div>
    </div>
  );
}

function DidRegistryTable({
  rows,
  page,
  totalPages,
  totalRows,
  onPageChange,
}: PaginatedTableProps<DidRow>) {
  return (
    <TablePanel
      title="DID Registry"
      empty="No DIDs registered yet."
      hasRows={totalRows > 0}
      page={page}
      totalPages={totalPages}
      totalRows={totalRows}
      onPageChange={onPageChange}
    >
      <table className="ledger-table w-full min-w-[920px] text-left text-xs">
        <thead className="font-mono uppercase">
          <tr>
            <HeaderCell>Device</HeaderCell>
            <HeaderCell>DID</HeaderCell>
            <HeaderCell>Public Key Prefix</HeaderCell>
            <HeaderCell>Status</HeaderCell>
            <HeaderCell>Registered At</HeaderCell>
            <HeaderCell>Issuer</HeaderCell>
            <HeaderCell>Details</HeaderCell>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.did} className="border-b border-line/20 last:border-0">
              <BodyCell>{row.device}</BodyCell>
              <BodyCell mono title={row.did}>{shortenMiddle(row.did, 34)}</BodyCell>
              <BodyCell mono>{row.publicKeyPrefix}</BodyCell>
              <BodyCell><StatusText value={row.status} /></BodyCell>
              <BodyCell>{formatIstDateTime(row.registeredAt)}</BodyCell>
              <BodyCell mono title={row.issuer}>{shortenMiddle(row.issuer, 28)}</BodyCell>
              <BodyCell>
                <details>
                  <summary className="cursor-pointer font-mono text-cyan">View</summary>
                  <div className="mt-2 break-all font-mono text-[11px] text-muted">{row.did}</div>
                </details>
              </BodyCell>
            </tr>
          ))}
        </tbody>
      </table>
    </TablePanel>
  );
}

function CredentialStatusTable({
  rows,
  page,
  totalPages,
  totalRows,
  onPageChange,
}: PaginatedTableProps<CredentialRow>) {
  return (
    <TablePanel
      title="Credential Status"
      empty="No credentials recorded yet."
      hasRows={totalRows > 0}
      page={page}
      totalPages={totalPages}
      totalRows={totalRows}
      onPageChange={onPageChange}
    >
      <table className="ledger-table w-full min-w-[980px] text-left text-xs">
        <thead className="font-mono uppercase">
          <tr>
            <HeaderCell>Credential ID</HeaderCell>
            <HeaderCell>Type</HeaderCell>
            <HeaderCell>Device</HeaderCell>
            <HeaderCell>DID or Subject</HeaderCell>
            <HeaderCell>Status</HeaderCell>
            <HeaderCell>Accumulator Version</HeaderCell>
            <HeaderCell>Updated At</HeaderCell>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.type}:${row.credentialId}`} className="border-b border-line/20 last:border-0">
              <BodyCell mono title={row.credentialId}>{shortenMiddle(row.credentialId, 32)}</BodyCell>
              <BodyCell>{row.type}</BodyCell>
              <BodyCell>{row.device}</BodyCell>
              <BodyCell mono title={row.subject}>{shortenMiddle(row.subject, 30)}</BodyCell>
              <BodyCell><StatusText value={row.status} /></BodyCell>
              <BodyCell mono>{row.accumulatorVersion}</BodyCell>
              <BodyCell>{formatIstDateTime(row.updatedAt)}</BodyCell>
            </tr>
          ))}
        </tbody>
      </table>
    </TablePanel>
  );
}

function AccumulatorStatePanel({ state }: { state: AccumulatorState | null }) {
  const rows = [
    ["Accumulator ID", state?.accumulator_id || state?.id || "Not available"],
    ["Version", state?.version ?? 0],
    ["Root", state?.root || "Not available"],
    ["Active Count", state?.active_count ?? 0],
    ["Revoked Count", state?.revoked_count ?? 0],
    ["Algorithm", state?.algorithm || "Not available"],
    ["Updated At", state?.updated_at || "Not available"],
  ];
  return (
    <div>
      <h3 className="mb-4 text-lg font-semibold">Accumulator State</h3>
      <div className="grid gap-3 lg:grid-cols-2">
        {rows.map(([label, value]) => {
          const text = String(value);
          const isRoot = label === "Root" && text !== "Not available";
          return (
            <div key={label} className="rounded border border-line/30 bg-background/45 p-3">
              <div className="font-mono text-[10px] uppercase text-muted">{label}</div>
              <div className="mt-2 break-all font-mono text-xs text-text" title={text}>
                {isRoot ? shortenMiddle(text, 44) : text}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AuditEventsTable({
  rows,
  page,
  totalPages,
  totalRows,
  onPageChange,
}: {
  rows: AuditRow[];
  page: number;
  totalPages: number;
  totalRows: number;
  onPageChange: (page: number) => void;
}) {
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-lg font-semibold">Audit Events</h3>
        <PaginationControls
          page={page}
          totalPages={totalPages}
          totalRows={totalRows}
          onPageChange={onPageChange}
        />
      </div>
      {rows.length ? (
        <div className="overflow-x-auto rounded border border-line/30 bg-background/45">
          <table className="ledger-table w-full min-w-[1120px] text-left text-xs">
            <thead className="font-mono uppercase">
              <tr>
                <HeaderCell>Time</HeaderCell>
                <HeaderCell>Event</HeaderCell>
                <HeaderCell>Service</HeaderCell>
                <HeaderCell>Device</HeaderCell>
                <HeaderCell>DID or Subject</HeaderCell>
                <HeaderCell>Credential ID</HeaderCell>
                <HeaderCell>Credential Type</HeaderCell>
                <HeaderCell>Result</HeaderCell>
                <HeaderCell>Reason</HeaderCell>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${row.time}:${row.event}:${row.credentialId}:${index}`} className="border-b border-line/20 last:border-0">
                  <BodyCell>{formatIstDateTime(row.time)}</BodyCell>
                  <BodyCell mono>{row.event}</BodyCell>
                  <BodyCell>{row.service}</BodyCell>
                  <BodyCell>{row.device}</BodyCell>
                  <BodyCell mono title={row.subject}>{shortenMiddle(row.subject, 28)}</BodyCell>
                  <BodyCell mono title={row.credentialId}>{shortenMiddle(row.credentialId, 28)}</BodyCell>
                  <BodyCell>{row.credentialType}</BodyCell>
                  <BodyCell><StatusText value={row.result} /></BodyCell>
                  <BodyCell>{row.reason}</BodyCell>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyPanel message="No audit events available yet." />
      )}
    </div>
  );
}

function TablePanel({
  title,
  empty,
  hasRows,
  children,
  page,
  totalPages,
  totalRows,
  onPageChange,
}: {
  title: string;
  empty: string;
  hasRows: boolean;
  children: React.ReactNode;
  page: number;
  totalPages: number;
  totalRows: number;
  onPageChange: (page: number) => void;
}) {
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-lg font-semibold">{title}</h3>
        <PaginationControls
          page={page}
          totalPages={totalPages}
          totalRows={totalRows}
          onPageChange={onPageChange}
        />
      </div>
      {hasRows ? (
        <div className="overflow-x-auto rounded border border-line/30 bg-background/45">{children}</div>
      ) : (
        <EmptyPanel message={empty} />
      )}
    </div>
  );
}

function HeaderCell({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2 text-[10px] font-semibold">{children}</th>;
}

function BodyCell({
  children,
  mono = false,
  title,
}: {
  children: React.ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <td className={`px-3 py-2 align-top text-text ${mono ? "font-mono" : ""}`} title={title}>
      {children}
    </td>
  );
}

function EmptyPanel({ message }: { message: string }) {
  return (
    <div className="rounded border border-line/35 bg-background/45 p-4 text-muted">
      {message}
    </div>
  );
}

function PaginationControls({
  page,
  totalPages,
  totalRows,
  onPageChange,
}: {
  page: number;
  totalPages: number;
  totalRows: number;
  onPageChange: (page: number) => void;
}) {
  if (totalRows <= tablePageSize) return null;
  return (
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
  );
}

function StatusText({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const color =
    normalized === "active" || normalized === "allow" || normalized === "recorded"
      ? "text-green"
      : normalized === "revoked" || normalized === "deny" || normalized === "denied" || normalized === "error"
        ? "text-danger"
        : "text-muted";
  return <span className={`font-mono ${color}`}>{value || "unknown"}</span>;
}

function toDidRow(device: DashboardDevice): DidRow {
  return {
    device: device.label || "Unknown Device",
    did: device.did || "Unknown",
    publicKeyPrefix: device.publicKeyPrefix || "Not available",
    status: device.status || "unknown",
    registeredAt: device.createdAt || "Not available",
    issuer: credentialIssuer(device.identityVc) || credentialIssuer(device.capabilityVc) || "Not available",
  };
}

function toCredentialRows(device: DashboardDevice): CredentialRow[] {
  const rows: CredentialRow[] = [];
  if (device.identityVc) {
    rows.push(toCredentialRow(device, device.identityVc, device.identityProof, "active"));
  }
  if (device.capabilityVc) {
    rows.push(toCredentialRow(device, device.capabilityVc, device.capabilityProof, device.capabilityStatus || "unknown"));
  }
  return rows;
}

function toCredentialRow(
  device: DashboardDevice,
  credential: VerifiableCredential,
  proof: AccumulatorProof | null | undefined,
  status: string,
): CredentialRow {
  return {
    credentialId: credential.id || "Unknown",
    type: credentialType(credential),
    device: device.label || "Unknown Device",
    subject: subjectDid(credential) || device.did || "Unknown",
    status,
    accumulatorVersion: String(proof?.version ?? credential.credentialStatus?.accumulatorVersion ?? "Not available"),
    updatedAt: credential.issuanceDate || device.updatedAt || "Not available",
  };
}

function toAuditRows(events: AuditEvent[], devices: DashboardDevice[]): AuditRow[] {
  return [...events]
    .sort((a, b) => eventTime(b).localeCompare(eventTime(a)))
    .map((event) => toAuditRow(event, devices));
}

function toAuditRow(event: AuditEvent, devices: DashboardDevice[]): AuditRow {
  const metadata = recordValue(event.metadata) || {};
  const details = recordValue(event.details) || {};
  const eventType = stringValue(event.event_type) || stringValue(event.event) || "EVENT";
  const credentialId =
    stringValue(event.credential_id) ||
    stringValue(event.credentialId) ||
    stringValue(metadata.credential_id) ||
    stringValue(metadata.credentialId) ||
    stringValue(metadata.vc_id) ||
    stringValue(metadata.vcId) ||
    "";
  const subject =
    stringValue(event.subject_did) ||
    stringValue(event.subjectDid) ||
    stringValue(event.subject) ||
    stringValue(metadata.subject_did) ||
    stringValue(metadata.subjectDid) ||
    stringValue(metadata.subject) ||
    "";
  const isBenchmark = stringValue(event.service) === "benchmark" || ["BENCHMARK_COMPLETED", "FABRIC_OPS_BENCHMARK"].includes(eventType);
  const device = isBenchmark ? undefined : deviceForEvent(event, devices, subject, credentialId);
  const result = auditResult(event, metadata, eventType);

  return {
    time: eventTime(event),
    event: eventType,
    service: stringValue(event.service) || "unknown",
    device: isBenchmark ? "Not applicable" : device?.label || stringValue(event.device_label) || "Unknown",
    subject: isBenchmark ? "Not applicable" : subject || device?.did || "Unknown",
    credentialId: credentialId || "Not applicable",
    credentialType: stringValue(event.credential_type) || stringValue(metadata.credential_type) || stringValue(details.credential_type) || credentialTypeForEvent(eventType, credentialId, device),
    result,
    reason: auditReason(event, metadata, details, eventType),
  };
}

function deviceForEvent(
  event: AuditEvent,
  devices: DashboardDevice[],
  subject: string,
  credentialId: string,
): DashboardDevice | undefined {
  const eventDeviceId = stringValue(event.device_id);
  const eventDeviceLabel = stringValue(event.device_label);
  return devices.find((device) => {
    if (eventDeviceId && device.id === eventDeviceId) return true;
    if (eventDeviceLabel && device.label === eventDeviceLabel) return true;
    if (subject && device.did === subject) return true;
    return Boolean(
      credentialId &&
        (device.identityVc?.id === credentialId || device.capabilityVc?.id === credentialId),
    );
  });
}

function credentialTypeForEvent(
  eventType: string,
  credentialId: string,
  device?: DashboardDevice,
): string {
  if (eventType.includes("IDENTITY")) return "Identity VC";
  if (eventType.includes("CAPABILITY") || eventType.startsWith("AUTH_")) return "Capability VC";
  if (eventType === "BENCHMARK_COMPLETED" || eventType === "FABRIC_OPS_BENCHMARK") return "Not applicable";
  if (credentialId && device?.identityVc?.id === credentialId) return "Identity VC";
  if (credentialId && device?.capabilityVc?.id === credentialId) return "Capability VC";
  return "Unknown";
}

function credentialType(credential: VerifiableCredential): string {
  const typeText = Array.isArray(credential.type) ? credential.type.join(" ") : "";
  if (typeText.includes("IdentityCredential")) return "Identity VC";
  if (typeText.includes("CapabilityCredential")) return "Capability VC";
  return "Credential";
}

function credentialIssuer(credential?: VerifiableCredential): string {
  return typeof credential?.issuer === "string" ? credential.issuer : "";
}

function subjectDid(credential: VerifiableCredential): string {
  const subject = credential.credentialSubject;
  return stringValue(subject?.id) || stringValue(subject?.subject_did) || stringValue(subject?.subjectDid) || "";
}

function resultForEvent(eventType: string): string {
  if (eventType === "VC_REVOKED") return "revoked";
  if (eventType === "AUTH_ALLOW") return "allow";
  if (eventType === "AUTH_DENY") return "deny";
  if (eventType === "BENCHMARK_COMPLETED" || eventType === "FABRIC_OPS_BENCHMARK") return "completed";
  return "recorded";
}

function auditResult(
  event: AuditEvent,
  metadata: Record<string, unknown>,
  eventType: string,
): string {
  const result =
    stringValue(event.result) ||
    stringValue(event.decision) ||
    stringValue(metadata.result) ||
    resultForEvent(eventType);
  if (eventType === "VC_REVOKED" && result === "benchmark capability revocation") return "revoked";
  return result;
}

function auditReason(
  event: AuditEvent,
  metadata: Record<string, unknown>,
  details: Record<string, unknown>,
  eventType: string,
): string {
  const candidates = [
    event.reason,
    event.detail,
    details.reason,
    details.result_reason,
    details.message,
    details.error,
    metadata.reason,
    metadata.detail,
    metadata.result_reason,
    metadata.message,
    metadata.error,
  ];
  for (const candidate of candidates) {
    const value = stringValue(candidate);
    if (value) return friendlyAuditReason(eventType, value);
  }
  return friendlyAuditReason(eventType, "");
}

function friendlyAuditReason(eventType: string, value: string): string {
  if (value) {
    if (eventType === "VC_REVOKED" && value === "revoked") return "capability revoked";
    return value;
  }
  const fallback: Record<string, string> = {
    AUTH_ALLOW: "authorized",
    AUTH_DENY: "Not available",
    VC_REVOKED: "capability revoked",
    CAPABILITY_VC_ISSUED: "capability issued",
    IDENTITY_VC_ISSUED: "identity credential issued",
    DID_REGISTERED: "DID registered",
    FABRIC_OPS_BENCHMARK: "Fabric ops benchmark completed",
    BENCHMARK_COMPLETED: "benchmark suite completed",
  };
  return fallback[eventType] || "Not available";
}

function eventTime(event: AuditEvent): string {
  return stringValue(event.created_at) || stringValue(event.timestamp) || "";
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

function pageCount(totalRows: number): number {
  return Math.max(1, Math.ceil(totalRows / tablePageSize));
}

function pageRows<T>(rows: T[], page: number): T[] {
  const start = (page - 1) * tablePageSize;
  return rows.slice(start, start + tablePageSize);
}

function shortenMiddle(value: string, maxLength: number): string {
  if (!value || value.length <= maxLength) return value;
  const side = Math.floor((maxLength - 3) / 2);
  return `${value.slice(0, side)}...${value.slice(value.length - side)}`;
}

function stringValue(value: unknown): string {
  return typeof value === "string" && value.trim() ? value : "";
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
