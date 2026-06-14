import type { LucideIcon } from "lucide-react";

export type PageKey =
  | "topology"
  | "wallet"
  | "ledger"
  | "security"
  | "performance";

export type ServiceHealth = {
  status: "ok" | "unknown" | "error";
  label: string;
  detail?: string;
  raw?: unknown;
};

export type DidCreateResponse = {
  did: string;
  public_key: string;
  did_document: Record<string, unknown>;
  fabric_warning?: string;
};

export type AccumulatorProof = {
  accumulator_id?: string;
  version?: number;
  root?: string;
  credential_hash?: string;
  proof?: unknown;
  [key: string]: unknown;
};

export type VerifiableCredential = {
  id?: string;
  type?: string[];
  issuer?: string;
  issuanceDate?: string;
  credentialSubject?: Record<string, unknown>;
  credentialStatus?: Record<string, unknown>;
  proof?: Record<string, unknown>;
  [key: string]: unknown;
};

export type AuditEvent = {
  event_id?: string;
  event_type?: string;
  event?: string;
  service?: string;
  device_id?: string | null;
  device_label?: string | null;
  subject_did?: string;
  credential_id?: string;
  credential_type?: string;
  decision?: string;
  result?: string;
  reason?: string;
  action?: string;
  detail?: string;
  details?: Record<string, unknown>;
  created_at?: string;
  timestamp?: string;
  metadata?: Record<string, unknown>;
  demo?: boolean;
  [key: string]: unknown;
};

export type DeviceAuditEvent = {
  event: string;
  service: string;
  device: string;
  subject_or_credential: string;
  result: string;
  created_at?: string;
};

export type DeviceAuditEventsPage = {
  items: DeviceAuditEvent[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  warnings?: string[];
};

export type AuditEventsPage = {
  items: AuditEvent[];
  events?: AuditEvent[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  warnings?: string[];
};

export type ScenarioResult = {
  id?: string;
  time: string;
  scenario_id?: string;
  scenario: string;
  device: string;
  device_id: string;
  expected: "allow" | "deny" | string;
  actual: "allow" | "deny" | "error" | string;
  reason: string;
  status: "pass" | "fail" | "error" | string;
};

export type ScenarioResultsPage = {
  items: ScenarioResult[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
};

export type BenchmarkOperation = {
  key: string;
  label: string;
  duration_ms: number;
  category: string;
  result?: string;
  notes?: string;
};

export type BenchmarkSummary = {
  full_lifecycle_ms?: number | null;
  auth_allow_ms?: number | null;
  revocation_ms?: number | null;
  proof_refresh_ms?: number | null;
  fabric_read_latency_ms?: number | null;
  fabric_write_latency_ms?: number | null;
  operations: BenchmarkOperation[];
  available_metrics?: string[];
  missing_metrics?: string[];
  diagnostic?: string | null;
  source?: string;
  profile?: string;
  mode?: string;
  benchmark_type?: string;
};

export type BenchmarkJob = {
  job_id: string;
  benchmark_type: "local" | "fabric_pipeline" | "fabric_ops" | string;
  status: "queued" | "running" | "completed" | "failed" | string;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  stdout_tail?: string;
  stderr_tail?: string;
  return_code?: number | null;
  summary?: BenchmarkSummary | null;
};

export type BenchmarkSuiteStep = {
  benchmark_type: "local" | "fabric_pipeline" | "fabric_ops" | string;
  status: "queued" | "running" | "completed" | "failed" | string;
  job_id?: string;
  profile?: string | null;
  mode?: string | null;
  summary?: BenchmarkSummary | null;
  error?: string | null;
};

export type BenchmarkComparisonEntry = {
  headline: {
    full_lifecycle_ms?: number | null;
    auth_allow_ms?: number | null;
    revocation_ms?: number | null;
    proof_refresh_ms?: number | null;
  };
  operations: BenchmarkOperation[];
  profile?: string | null;
  mode?: string | null;
};

export type BenchmarkSuiteSummary = {
  comparison: {
    local?: BenchmarkComparisonEntry | null;
    fabric?: BenchmarkComparisonEntry | null;
  };
  fabric_ops?: {
    headline: {
      total_operations_ms?: number | null;
      ledger_read_ms?: number | null;
      ledger_write_ms?: number | null;
      accumulator_read_ms?: number | null;
    };
    operations: BenchmarkOperation[];
    profile?: string | null;
    mode?: string | null;
  } | null;
  constrained?: ConstrainedBenchmarkSummary | null;
  revocation_connectivity?: RevocationConnectivitySummary | null;
  fabric_tuning?: FabricTuningSummary | null;
  resource_usage?: ResourceUsageRow[];
  resource_usage_available?: boolean;
  resource_usage_reason?: string | null;
};

export type BenchmarkSuite = {
  suite_job_id: string;
  status: "queued" | "running" | "completed" | "failed" | string;
  started_at?: string | null;
  finished_at?: string | null;
  current_step?: "local" | "fabric_pipeline" | "fabric_ops" | string | null;
  error?: string | null;
  steps: BenchmarkSuiteStep[];
  combined_summary?: BenchmarkSuiteSummary | null;
};

export type ConstrainedProfileResult = {
  profile: string;
  label: string;
  cpu_limit: string;
  memory_limit: string;
  full_lifecycle_ms?: number | null;
  auth_allow_ms?: number | null;
  proof_refresh_ms?: number | null;
  payload_size_bytes?: number | null;
  peak_cpu_percent?: number | null;
  peak_ram_mb?: number | null;
  status: string;
  error?: string | null;
};

export type ConstrainedBenchmarkSummary = {
  profiles: ConstrainedProfileResult[];
  generated_at?: string;
  source?: string;
  profile?: string;
  mode?: string;
  error?: string | null;
};

export type RevocationConnectivityTest = {
  test: string;
  actor?: string | null;
  expected: "allow" | "deny" | "blocked" | "not_supported" | "network_error" | "connection_timeout" | string;
  actual: "allow" | "deny" | "blocked" | "not_supported" | "network_error" | "connection_timeout" | string;
  reason: string;
  latency_ms?: number | null;
  status: "pass" | "fail" | "not-supported" | "not_supported" | string;
  details?: Record<string, unknown>;
};

export type RevocationConnectivitySummary = {
  tests: RevocationConnectivityTest[];
  debug_unsupported_tests?: RevocationConnectivityTest[];
  generated_at?: string;
  source?: string;
  profile?: string;
  mode?: string;
  error?: string | null;
};

export type FabricTuningProfile = {
  profile_id: string;
  label: string;
  description?: string | null;
  block_size?: string | null;
  batch_timeout?: string | null;
  endorsement_policy?: string | null;
  full_lifecycle_ms?: number | null;
  auth_allow_ms?: number | null;
  revocation_ms?: number | null;
  proof_refresh_ms?: number | null;
  ledger_read_ms?: number | null;
  ledger_write_ms?: number | null;
  read_p50_ms?: number | null;
  read_p95_ms?: number | null;
  write_p50_ms?: number | null;
  write_p95_ms?: number | null;
  read_tps?: number | null;
  write_tps?: number | null;
  tps?: number | null;
  cpu?: number | null;
  ram?: number | null;
  cpu_peak?: number | null;
  ram_peak?: number | null;
  status: string;
  reason?: string | null;
  notes?: string;
  error?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  pipeline_summary_path?: string | null;
  fabric_ops_summary_path?: string | null;
  write_pressure_summary_path?: string | null;
  write_pressure?: FabricWritePressureSummary | null;
};

export type FabricWritePressureGroup = {
  operation_type: string;
  count?: number | null;
  successful_writes?: number | null;
  failures?: number | null;
  average_latency_ms?: number | null;
  p50_latency_ms?: number | null;
  p95_latency_ms?: number | null;
};

export type FabricWritePressureSummary = {
  status?: string | null;
  total_writes?: number | null;
  successful_writes?: number | null;
  failed_writes?: number | null;
  total_duration_ms?: number | null;
  average_write_latency_ms?: number | null;
  p50_write_latency_ms?: number | null;
  p95_write_latency_ms?: number | null;
  min_write_latency_ms?: number | null;
  max_write_latency_ms?: number | null;
  writes_per_second?: number | null;
  groups?: FabricWritePressureGroup[];
  error?: string | null;
};

export type FabricTuningSummary = {
  profiles: FabricTuningProfile[];
  generated_at?: string;
  source?: string;
  profile?: string;
  mode?: string;
  error?: string | null;
};

export type ResourceUsageRow = {
  service: string;
  section: string;
  avg_cpu_percent?: number | null;
  peak_cpu_percent?: number | null;
  avg_memory_mb?: number | null;
  peak_memory_mb?: number | null;
  sample_count?: number | null;
};

export type AccumulatorState = {
  accumulator_id?: string;
  id?: string;
  version?: number;
  root?: string;
  active_count?: number;
  revoked_count?: number;
  algorithm?: string;
  updated_at?: string;
  [key: string]: unknown;
};

export type DashboardSummary = {
  registered_devices: number;
  active_credentials: number;
  revoked_credentials: number;
  accumulator_version?: number | string | null;
  accumulator_root?: string | null;
  accumulator_state_ok?: boolean;
  accumulator_state_error?: string | null;
  issuer_health?: string;
  verifier_health?: string;
  fabric_adapter_health?: string;
  fabric_network?: string;
  warnings?: string[];
};

export type CleanStateCommand = {
  name: string;
  ok: boolean;
  stdout: string;
  stderr: string;
  duration_ms: number;
};

export type CleanStateResponse = {
  ok: boolean;
  dashboard_cleared?: boolean;
  fabric_reset?: boolean;
  commands?: CleanStateCommand[];
  message?: string;
  error?: string;
};

export type DeviceKeyPair = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBase64: string;
};

export type DashboardDeviceStatus = "pending" | "active" | "revoked" | "error";

export type DashboardDevice = {
  id: string;
  label: string;
  status: DashboardDeviceStatus;
  did?: string;
  didDocument?: Record<string, unknown>;
  publicKeyPrefix?: string;
  identityVc?: VerifiableCredential;
  identityProof?: AccumulatorProof | null;
  capabilityVc?: VerifiableCredential;
  capabilityProof?: AccumulatorProof | null;
  capabilityStatus?: "not-issued" | "active" | "revoked";
  latestDecision?: string;
  latestReason?: string;
  error?: string;
  createdAt?: string;
  updatedAt?: string;
};

export type DemoSession = {
  selectedDeviceId?: string;
  devices: DashboardDevice[];
  eventLog: AuditEvent[];
  accumulatorState?: AccumulatorState;
  ledgerSummary?: DashboardSummary;
  demoData: boolean;
};

export type NavItem = {
  key: PageKey;
  label: string;
  icon: LucideIcon;
};

export type ActionResult = {
  ok: boolean;
  title: string;
  message: string;
};
