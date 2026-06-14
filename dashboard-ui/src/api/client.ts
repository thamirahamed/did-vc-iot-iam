import axios, { AxiosError } from "axios";
import type {
  AccumulatorState,
  AuditEvent,
  AuditEventsPage,
  CleanStateResponse,
  DeviceAuditEventsPage,
  BenchmarkJob,
  BenchmarkSuite,
  DashboardDevice,
  DashboardSummary,
  ScenarioResult,
  ScenarioResultsPage,
  ServiceHealth,
} from "../types";

const dashboardApiUrl =
  import.meta.env.VITE_DASHBOARD_API_URL || "http://localhost:8020";

const shouldUseViteProxy =
  window.location.port === "5173" && window.location.hostname === "localhost";

const dashboardBase = shouldUseViteProxy ? "/api/dashboard" : dashboardApiUrl;
const dashboard = axios.create({ baseURL: dashboardBase, timeout: 30000 });

export type LedgerSummary = DashboardSummary;

export async function getDashboardHealth(): Promise<ServiceHealth> {
  return health("Dashboard API", () => dashboard.get("/health"));
}

export async function getLedgerSummary(): Promise<LedgerSummary> {
  const response = await dashboard.get<LedgerSummary>("/dashboard/ledger/summary");
  return response.data;
}

export async function getServiceHealthFromSummary(): Promise<{
  issuer: ServiceHealth;
  verifier: ServiceHealth;
  fabricAdapter: ServiceHealth;
}> {
  try {
    const summary = await getLedgerSummary();
    return {
      issuer: healthFromText("Issuer", summary.issuer_health),
      verifier: healthFromText("Verifier", summary.verifier_health),
      fabricAdapter: healthFromText("Fabric Adapter", summary.fabric_adapter_health),
    };
  } catch (error) {
    const detail = errorMessage(error);
    return {
      issuer: { status: "error", label: "Issuer", detail },
      verifier: { status: "error", label: "Verifier", detail },
      fabricAdapter: { status: "error", label: "Fabric Adapter", detail },
    };
  }
}

export function serviceHealthFromLedgerSummary(summary: DashboardSummary): {
  issuer: ServiceHealth;
  verifier: ServiceHealth;
  fabricAdapter: ServiceHealth;
} {
  return {
    issuer: healthFromText("Issuer", summary.issuer_health),
    verifier: healthFromText("Verifier", summary.verifier_health),
    fabricAdapter: healthFromText("Fabric Adapter", summary.fabric_adapter_health),
  };
}

export async function getDashboardDevices(): Promise<DashboardDevice[]> {
  const response = await dashboard.get<{ devices: BackendDevice[] }>(
    "/dashboard/devices",
  );
  return response.data.devices.map(mapDevice);
}

export async function createDashboardDevice(label?: string): Promise<DashboardDevice> {
  const response = await dashboard.post<{ device: BackendDevice }>("/dashboard/devices", {
    label,
  });
  return mapDevice(response.data.device);
}

export async function getDashboardDevice(deviceId: string): Promise<DashboardDevice> {
  const response = await dashboard.get<{ device: BackendDevice }>(
    `/dashboard/devices/${deviceId}`,
  );
  return mapDevice(response.data.device);
}

export async function issueIdentityForDevice(deviceId: string): Promise<DashboardDevice> {
  const response = await dashboard.post<{ device: BackendDevice }>(
    `/dashboard/devices/${deviceId}/issue-identity`,
    {},
  );
  return mapDevice(response.data.device);
}

export async function issueCapabilityForDevice(
  deviceId: string,
  action = "read",
  resource = "iot:device:example",
): Promise<DashboardDevice> {
  const response = await dashboard.post<{ device: BackendDevice }>(
    `/dashboard/devices/${deviceId}/issue-capability`,
    { action, resource },
  );
  return mapDevice(response.data.device);
}

export async function refreshProofForDevice(deviceId: string): Promise<DashboardDevice> {
  const response = await dashboard.post<{ device: BackendDevice }>(
    `/dashboard/devices/${deviceId}/refresh-proof`,
    {},
  );
  return mapDevice(response.data.device);
}

export async function authorizeDevice(params: {
  deviceId: string;
  action?: string;
  resource?: string;
  tamperSignature?: boolean;
}): Promise<{ decision: { decision: string; reason: string }; device: DashboardDevice }> {
  const response = await dashboard.post<{
    decision: { decision: string; reason: string };
    device: BackendDevice;
  }>(`/dashboard/devices/${params.deviceId}/authorize`, {
    action: params.action || "read",
    resource: params.resource || "iot:device:example",
    tamper_signature: Boolean(params.tamperSignature),
  });
  return { decision: response.data.decision, device: mapDevice(response.data.device) };
}

export async function revokeDeviceCapability(
  deviceId: string,
  reason = "dashboard capability revocation",
): Promise<DashboardDevice> {
  const response = await dashboard.post<{ device: BackendDevice }>(
    `/dashboard/devices/${deviceId}/revoke`,
    { reason },
  );
  return mapDevice(response.data.device);
}

export async function restoreDeviceAccess(deviceId: string): Promise<DashboardDevice> {
  const response = await dashboard.post<{ device: BackendDevice }>(
    `/dashboard/devices/${deviceId}/restore-access`,
    {},
  );
  return mapDevice(response.data.device);
}

export async function getAccumulatorState(): Promise<AccumulatorState | null> {
  try {
    const response = await dashboard.get<AccumulatorState>(
      "/dashboard/accumulator/state",
    );
    return response.data;
  } catch (error) {
    if (isMissingEndpoint(error)) return null;
    throw error;
  }
}

export async function getAuditEvents(
  page = 1,
  pageSize = 15,
): Promise<AuditEventsPage> {
  const response = await dashboard.get<AuditEventsPage>(
    "/dashboard/audit/events",
    { params: { page, page_size: pageSize } },
  );
  return {
    ...response.data,
    items: response.data.items || response.data.events || [],
    warnings: response.data.warnings || [],
  };
}

export async function getDeviceAuditEvents(
  deviceId: string,
  page = 1,
  pageSize = 10,
): Promise<DeviceAuditEventsPage> {
  const response = await dashboard.get<DeviceAuditEventsPage>(
    `/dashboard/devices/${deviceId}/audit-events`,
    { params: { page, page_size: pageSize } },
  );
  return response.data;
}

export async function getScenarioResults(
  page = 1,
  pageSize = 10,
): Promise<ScenarioResultsPage> {
  const response = await dashboard.get<ScenarioResultsPage>(
    "/dashboard/scenarios/results",
    { params: { page, page_size: pageSize } },
  );
  return response.data;
}

export async function runSecurityScenario(
  scenarioId: string,
  deviceId: string,
): Promise<{ result: ScenarioResult; device: DashboardDevice }> {
  const response = await dashboard.post<{
    result: ScenarioResult;
    device: BackendDevice;
  }>(`/dashboard/scenarios/${scenarioId}`, { device_id: deviceId });
  return { result: response.data.result, device: mapDevice(response.data.device) };
}

export async function startBenchmark(params: {
  benchmarkType:
    | "local"
    | "fabric_pipeline"
    | "fabric_ops"
    | "constrained"
    | "revocation_connectivity"
    | "fabric_tuning";
  runs?: number;
  warmupRuns?: number;
}): Promise<{ job_id: string; status: string }> {
  const response = await dashboard.post<{ job_id: string; status: string }>(
    "/dashboard/performance/benchmarks/run",
    {
      benchmark_type: params.benchmarkType,
      runs: params.runs ?? 1,
      warmup_runs: params.warmupRuns ?? 0,
    },
  );
  return response.data;
}

export async function startConstrainedBenchmark(params: {
  runs?: number;
  warmupRuns?: number;
}): Promise<{ job_id: string; status: string }> {
  const response = await dashboard.post<{ job_id: string; status: string }>(
    "/dashboard/performance/benchmarks/run-constrained",
    {
      runs: params.runs ?? 1,
      warmup_runs: params.warmupRuns ?? 0,
    },
  );
  return response.data;
}

export async function getLatestConstrainedBenchmark(): Promise<BenchmarkJob | null> {
  const response = await dashboard.get<{ job: BenchmarkJob | null }>(
    "/dashboard/performance/benchmarks/constrained/latest",
  );
  return response.data.job;
}

export async function startFabricTuningBenchmark(params: {
  runs?: number;
  warmupRuns?: number;
}): Promise<{ job_id: string; status: string }> {
  const response = await dashboard.post<{ job_id: string; status: string }>(
    "/dashboard/performance/benchmarks/run-tuning",
    {
      runs: params.runs ?? 1,
      warmup_runs: params.warmupRuns ?? 0,
    },
  );
  return response.data;
}

export async function getLatestFabricTuningBenchmark(): Promise<BenchmarkJob | null> {
  const response = await dashboard.get<{ job: BenchmarkJob | null }>(
    "/dashboard/performance/benchmarks/tuning/latest",
  );
  return response.data.job;
}

export async function startRevocationConnectivityBenchmark(params: {
  runs?: number;
  warmupRuns?: number;
}): Promise<{ job_id: string; status: string }> {
  const response = await dashboard.post<{ job_id: string; status: string }>(
    "/dashboard/performance/benchmarks/run-revocation-connectivity",
    {
      runs: params.runs ?? 1,
      warmup_runs: params.warmupRuns ?? 0,
    },
  );
  return response.data;
}

export async function getLatestRevocationConnectivityBenchmark(): Promise<BenchmarkJob | null> {
  const response = await dashboard.get<{ job: BenchmarkJob | null }>(
    "/dashboard/performance/benchmarks/revocation-connectivity/latest",
  );
  return response.data.job;
}

export async function getBenchmarkJob(jobId: string): Promise<BenchmarkJob> {
  const response = await dashboard.get<BenchmarkJob>(
    `/dashboard/performance/benchmarks/${jobId}`,
  );
  return response.data;
}

export async function getLatestBenchmark(): Promise<BenchmarkJob | null> {
  const response = await dashboard.get<{ job: BenchmarkJob | null }>(
    "/dashboard/performance/benchmarks/latest",
  );
  return response.data.job;
}

export async function startBenchmarkSuite(params: {
  runs?: number;
  warmupRuns?: number;
}): Promise<{ suite_job_id: string; status: string }> {
  const response = await dashboard.post<{ suite_job_id: string; status: string }>(
    "/dashboard/performance/benchmarks/run-all",
    {
      runs: params.runs ?? 1,
      warmup_runs: params.warmupRuns ?? 0,
    },
  );
  return response.data;
}

export async function getBenchmarkSuite(suiteJobId: string): Promise<BenchmarkSuite> {
  const response = await dashboard.get<BenchmarkSuite>(
    `/dashboard/performance/benchmarks/suites/${suiteJobId}`,
  );
  return response.data;
}

export async function getLatestBenchmarkSuite(): Promise<BenchmarkSuite | null> {
  const response = await dashboard.get<{ suite: BenchmarkSuite | null }>(
    "/dashboard/performance/benchmarks/latest-suite",
  );
  return response.data.suite;
}

export async function cleanDashboardState(params: {
  confirm: string;
}): Promise<CleanStateResponse> {
  const response = await dashboard.post<CleanStateResponse>("/dashboard/clean-state", {
    confirm: params.confirm,
  });
  return response.data;
}

async function health(
  label: string,
  request: () => Promise<{ data: unknown }>,
): Promise<ServiceHealth> {
  try {
    const response = await request();
    return healthFromPayload(label, response.data);
  } catch (error) {
    return {
      status: "error",
      label,
      detail: errorMessage(error),
    };
  }
}

function healthFromPayload(label: string, payload: unknown): ServiceHealth {
  const body = (payload || {}) as Record<string, unknown>;
  const ok = body.status === "ok" || body.ok === true;
  return {
    status: ok ? "ok" : "unknown",
    label,
    detail: ok ? "Connected" : "Unknown",
    raw: payload,
  };
}

function healthFromText(label: string, value: string | undefined): ServiceHealth {
  const ok = value === "ok" || value === "connected";
  return {
    status: ok ? "ok" : "unknown",
    label,
    detail: ok ? "Connected" : "Unknown",
    raw: value,
  };
}

type BackendDevice = {
  id: string;
  label: string;
  did?: string;
  status?: DashboardDevice["status"];
  public_key_prefix?: string;
  public_key?: string;
  did_document?: Record<string, unknown>;
  identity_vc?: Record<string, unknown> | null;
  identity_proof?: Record<string, unknown> | null;
  capability_vc?: Record<string, unknown> | null;
  capability_proof?: Record<string, unknown> | null;
  credential_status?: DashboardDevice["capabilityStatus"];
  last_decision?: string | null;
  last_reason?: string | null;
  last_error?: string | null;
  created_at?: string;
  updated_at?: string;
};

function mapDevice(device: BackendDevice): DashboardDevice {
  return {
    id: device.id,
    label: device.label,
    status: device.status || "active",
    did: device.did,
    didDocument: device.did_document,
    publicKeyPrefix: device.public_key_prefix || device.public_key?.slice(0, 16),
    identityVc: device.identity_vc || undefined,
    identityProof: device.identity_proof || null,
    capabilityVc: device.capability_vc || undefined,
    capabilityProof: device.capability_proof || null,
    capabilityStatus: device.credential_status || "not-issued",
    latestDecision: device.last_decision || undefined,
    latestReason: device.last_reason || undefined,
    error: device.last_error || undefined,
    createdAt: device.created_at,
    updatedAt: device.updated_at,
  };
}

function isMissingEndpoint(error: unknown): boolean {
  return axios.isAxiosError(error) && [404, 405].includes(error.response?.status || 0);
}

export function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<{ detail?: string }>;
    return (
      axiosError.response?.data?.detail ||
      axiosError.message ||
      "Request failed"
    );
  }
  if (error instanceof Error) return error.message;
  return "Request failed";
}
