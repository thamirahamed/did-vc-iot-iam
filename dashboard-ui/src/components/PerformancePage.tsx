import { type CSSProperties, useEffect, useMemo, useState } from "react";
import { BarChart3, RefreshCw } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  errorMessage,
  getBenchmarkSuite,
  getLatestBenchmarkSuite,
  startBenchmarkSuite,
} from "../api/client";
import type {
  BenchmarkComparisonEntry,
  BenchmarkOperation,
  BenchmarkSuite,
  ConstrainedBenchmarkSummary,
  FabricTuningSummary,
  ResourceUsageRow,
  RevocationConnectivitySummary,
} from "../types";

const comparisonOrder = [
  "did_create",
  "did_resolve",
  "identity_issue",
  "capability_issue",
  "auth_allow",
  "wrong_action_deny",
  "revoke_capability",
  "revoked_deny",
  "replacement_capability_issue",
  "proof_refresh",
  "replacement_allow",
  "full_lifecycle",
];

const baselineLabel = "Centralised Baseline";

const chartPalette = {
  fabric: "#00D8FF",
  cyanSoft: "#16F4D0",
  baseline: "#8B5CFF",
  proof: "#8B5CFF",
  pink: "#FF4FD8",
  revocation: "#FF8A3D",
  success: "#19D6A3",
  danger: "#FF4D6D",
  warning: "#FFB84D",
  muted: "#9DA7C7",
  grid: "#1B1E3A",
  cursor: "rgba(139, 92, 255, 0.12)",
  tooltipBackground: "#12142B",
  tooltipBorder: "rgba(42,45,85,0.92)",
  text: "#F2F4FF",
};

const resourceServiceOrder = [
  "benchmark-agent-gateway",
  "benchmark-agent-constrained",
  "benchmark-agent-low",
  "benchmark-agent-tiny",
  "issuer",
  "verifier",
  "fabric-adapter",
  "peer0.org1.example.com",
  "peer0.org2.example.com",
  "dashboard-api",
];

const resourceServiceNames: Record<string, string> = {
  "benchmark-agent-gateway": "Gateway device agent",
  "benchmark-agent-constrained": "Constrained device agent",
  "benchmark-agent-low": "Low resource device agent",
  "benchmark-agent-tiny": "Tiny IoT device agent",
  issuer: "Issuer service",
  verifier: "Verifier service",
  "fabric-adapter": "Fabric adapter",
  "peer0.org1.example.com": "Fabric peer org1",
  "peer0.org2.example.com": "Fabric peer org2",
  "dashboard-api": "Dashboard API",
};

const resourceChartServiceNames: Record<string, string> = {
  "benchmark-agent-gateway": "Gateway agent",
  "benchmark-agent-constrained": "Constrained agent",
  "benchmark-agent-low": "Low resource agent",
  "benchmark-agent-tiny": "Tiny IoT agent",
  issuer: "Issuer",
  verifier: "Verifier",
  "fabric-adapter": "Fabric adapter",
  "peer0.org1.example.com": "Peer org1",
  "peer0.org2.example.com": "Peer org2",
  "dashboard-api": "Dashboard API",
};

const pipelineStages = [
  {
    key: "identity",
    shortLabel: "Identity",
    label: "Identity setup",
    operationKeys: ["did_create", "did_resolve"],
    includes: "Includes DID registration and DID resolution.",
  },
  {
    key: "issuance",
    shortLabel: "Issuance",
    label: "VC issuance",
    operationKeys: ["identity_issue", "capability_issue"],
    includes: "Includes identity VC and capability VC issuance.",
  },
  {
    key: "auth",
    shortLabel: "Auth",
    label: "Authorization checks",
    operationKeys: ["auth_allow", "wrong_action_deny"],
    includes: "Includes valid access verification and wrong-action denial.",
  },
  {
    key: "recovery",
    shortLabel: "Recovery",
    label: "Revocation and recovery",
    operationKeys: [
      "revoke_capability",
      "revoked_deny",
      "replacement_capability_issue",
      "proof_refresh",
      "replacement_allow",
    ],
    includes: "Includes revocation, stale credential denial, replacement issuance, proof refresh, and restored access.",
  },
];

const operationDetails: Record<string, string> = {
  did_create: "Creates and anchors the device DID record.",
  did_resolve: "Reads the DID document or registry entry.",
  identity_issue: "Issues the identity credential for the device.",
  capability_issue: "Issues the access capability credential.",
  auth_allow: "Verifier checks signature, proof, capability, expiry, and revocation state.",
  wrong_action_deny: "Verifier rejects a request outside the capability claim.",
  revoke_capability: "Issuer revokes the current capability credential and updates accumulator state.",
  revoked_deny: "Verifier rejects the revoked or stale credential.",
  replacement_capability_issue: "Issues a fresh capability credential after revocation.",
  proof_refresh: "Refreshes proof against the latest accumulator root.",
  replacement_allow: "Verifies access after replacement credential issuance.",
  full_lifecycle: "Total time for one complete benchmark iteration.",
};

const fabricOpsDetails: Record<string, string> = {
  audit_write: "Writes an audit record to the ledger.",
  accumulator_read: "Reads current accumulator root and version.",
  accumulator_write: "Updates accumulator root and version.",
  credential_read: "Reads credential status from ledger state.",
  credential_write: "Writes active or revoked credential status.",
  fabric_register_credential_with_accumulator: "Combined write for credential status plus accumulator state.",
  fabric_revoke_credential_with_accumulator: "Combined revocation and accumulator update.",
  fabric_ping: "Basic adapter to chaincode reachability check.",
  did_read: "Reads a DID registry entry from ledger state.",
  did_write: "Writes a DID registry entry to ledger state.",
  fabric_revoke_credential: "Marks a credential revoked in ledger state.",
  fabric_list_audit_events: "Lists recent audit records from ledger state.",
};

const revocationTestDetails: Record<string, string> = {
  "Valid proof authorization": "Checks that a device agent with current identity and capability proofs is authorized normally.",
  "Active stale proof denial": "benchmark-device-01 is still active, but its accumulator proof is old because benchmark-device-02 changed the accumulator state. Verifier should deny as stale.",
  "Active stale proof refresh recovery": "benchmark-device-01 refreshes its proof from the issuer and retries. Access should be allowed after proof update.",
  "Revoked stale proof denial": "benchmark-device-01 tries to use an old proof after its capability credential has been revoked. Access should be denied.",
  "Revoked proof refresh blocked": "benchmark-device-01 asks the issuer to refresh proof for a revoked credential. Issuer must block it.",
  "Restore access recovery": "A fresh replacement capability credential is issued after revocation. Access should work only with the new credential and proof.",
  "Delayed reconnect refresh": "Device agent delays proof refresh to simulate reconnect after being out of date, then refreshes and authorizes successfully.",
  "Latency affected proof refresh": "Uses Docker proxy latency between device agent and issuer/verifier. Proof refresh and authorization should still complete.",
  "Connection disruption recovery": "Simulates temporary verifier connection disruption, then clears it and confirms the device agent can recover.",
};

const categoryColors = [
  chartPalette.fabric,
  chartPalette.cyanSoft,
  chartPalette.proof,
  chartPalette.revocation,
  chartPalette.pink,
  chartPalette.success,
  chartPalette.warning,
];

const categoryDetails: Record<string, string> = {
  Fabric: "Basic Fabric adapter or chaincode reachability operation.",
  "Fabric DID": "Ledger operations that read or write DID registry state.",
  "Credential Status": "Ledger operations that read or write credential status records.",
  Accumulator: "Reads or writes accumulator root, version, active count, and revoked count.",
  Audit: "Writes or lists audit records used for traceability.",
  Combined: "Chaincode operations that update credential status and accumulator state in one transaction.",
  Revocation: "Credential revocation specific ledger operation.",
};

const benchmarkSteps = [
  { type: "local", label: "Centralised Baseline" },
  { type: "fabric_pipeline", label: "Fabric Pipeline Benchmark" },
  { type: "fabric_ops", label: "Fabric Ops Benchmark" },
  { type: "constrained", label: "Constrained Device Emulation" },
  { type: "revocation_connectivity", label: "Revocation Connectivity" },
  { type: "fabric_tuning", label: "Fabric Tuning" },
];

export default function PerformancePage() {
  const [suite, setSuite] = useState<BenchmarkSuite | null>(null);
  const [runningSuiteId, setRunningSuiteId] = useState<string>();
  const [loadingLatest, setLoadingLatest] = useState(false);
  const [error, setError] = useState("");
  const [opsPage, setOpsPage] = useState(1);
  const [tableTooltip, setTableTooltip] = useState<TableTooltipState | null>(null);

  useEffect(() => {
    refreshLatest();
  }, []);

  useEffect(() => {
    if (!runningSuiteId) return;
    const timer = window.setInterval(async () => {
      try {
        const next = await getBenchmarkSuite(runningSuiteId);
        setSuite(next);
        if (next.status === "completed" || next.status === "failed" || next.status === "completed_with_errors") {
          setRunningSuiteId(undefined);
          setError(next.status === "failed" ? next.error || "Benchmark suite failed" : "");
        }
      } catch (err) {
        setError(errorMessage(err));
        setRunningSuiteId(undefined);
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [runningSuiteId]);

  const running = Boolean(runningSuiteId);
  const fabricPipelineStep = suite?.steps.find((item) => item.benchmark_type === "fabric_pipeline");
  const fabricPipelineFailed = fabricPipelineStep?.status === "failed";
  const summary = useMemo(() => {
    if (running) return null;
    const base = suite?.combined_summary || null;
    if (!base || !fabricPipelineFailed) return base;
    return {
      ...base,
      comparison: {
        ...base.comparison,
        fabric: null,
      },
    };
  }, [fabricPipelineFailed, running, suite?.combined_summary]);
  const comparisonRows = useMemo(() => buildComparisonRows(summary), [summary]);
  const stageRows = useMemo(() => buildStageRows(summary), [summary]);
  const fabricOps = summary?.fabric_ops || null;
  const constrained = summary?.constrained || null;
  const revocationConnectivity = summary?.revocation_connectivity || null;
  const fabricTuning = summary?.fabric_tuning || null;
  const resourceUsage = summary?.resource_usage || [];
  const resourceUsageReason = summary?.resource_usage_reason || null;
  const fabricOpsOperations = fabricOps?.operations || [];
  const categoryRows = useMemo(() => buildFabricCategoryRows(fabricOpsOperations), [fabricOpsOperations]);
  const totalOpsPages = Math.max(1, Math.ceil(fabricOpsOperations.length / 15));
  const visibleOps = fabricOpsOperations.slice((opsPage - 1) * 15, opsPage * 15);

  useEffect(() => {
    setOpsPage((page) => Math.min(page, totalOpsPages));
  }, [totalOpsPages]);
  const localLifecycle = summary?.comparison.local?.headline.full_lifecycle_ms;
  const fabricLifecycle = summary?.comparison.fabric?.headline.full_lifecycle_ms;
  const lifecycleDifference =
    localLifecycle !== null &&
    localLifecycle !== undefined &&
    fabricLifecycle !== null &&
    fabricLifecycle !== undefined
      ? fabricLifecycle - localLifecycle
      : null;
  const cards: MetricCardData[] = [
    {
      label: "Centralised Baseline full lifecycle",
      value: formatDuration(localLifecycle),
      color: chartPalette.baseline,
    },
    {
      label: "Fabric full lifecycle",
      value: formatDuration(fabricLifecycle),
      color: chartPalette.fabric,
    },
    {
      label: "Lifecycle overhead",
      value: formatLifecycleDifference(lifecycleDifference),
      color: lifecycleDifference === null ? chartPalette.muted : lifecycleDifference <= 0 ? chartPalette.success : chartPalette.revocation,
    },
    {
      label: "Fabric valid access",
      value: formatDuration(summary?.comparison.fabric?.headline.auth_allow_ms),
      color: chartPalette.success,
    },
    {
      label: "Fabric revocation",
      value: formatDuration(summary?.comparison.fabric?.headline.revocation_ms),
      color: chartPalette.revocation,
    },
    {
      label: "Fabric proof refresh",
      value: formatDuration(summary?.comparison.fabric?.headline.proof_refresh_ms),
      color: chartPalette.proof,
    },
    {
      label: "Ledger read latency",
      value: formatDuration(fabricOps?.headline.ledger_read_ms),
      color: chartPalette.fabric,
    },
    {
      label: "Ledger write latency",
      value: formatDuration(fabricOps?.headline.ledger_write_ms),
      color: chartPalette.revocation,
    },
  ];

  const statusText = running
    ? "Running new benchmark suite"
    : suite?.finished_at
      ? `Latest suite finished ${formatDateTime(suite.finished_at)}`
      : "No benchmark suite result yet.";

  async function runAll() {
    if (running) return;
    setError("");
    try {
      const response = await startBenchmarkSuite({ runs: 1, warmupRuns: 0 });
      setRunningSuiteId(response.suite_job_id);
      setSuite({
        suite_job_id: response.suite_job_id,
        status: response.status,
        current_step: null,
        steps: [],
        combined_summary: null,
      });
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function refreshLatest() {
    setLoadingLatest(true);
    try {
      setSuite(await getLatestBenchmarkSuite());
      setError("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoadingLatest(false);
    }
  }

  function showTableTooltip(text: string | undefined, event: React.MouseEvent) {
    if (!text) return;
    setTableTooltip({
      text,
      x: event.clientX + 14,
      y: event.clientY + 14,
    });
  }

  function hideTableTooltip() {
    setTableTooltip(null);
  }

  return (
    <div className="space-y-5 p-6">
      <section className="glass-card rounded p-5">
        <div className="flex items-center gap-3">
          <BarChart3 className="text-cyan" />
          <div>
            <h2 className="text-xl font-semibold">Performance and Evaluation</h2>
            <p className="font-mono text-xs text-muted">
              Compare pipeline latency, revocation cost, proof refresh speed, and ledger operation overhead.
            </p>
          </div>
        </div>
      </section>

      <section className="glass-card rounded p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold">Benchmark controls</h3>
            {running ? <div className="skeleton-line mt-2 h-4 w-56" /> : <p className="mt-1 text-sm text-muted">{statusText}</p>}
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={runAll}
              disabled={running}
              className="rounded border border-cyan/45 bg-cyan/10 px-4 py-2 font-mono text-xs font-semibold text-cyan transition hover:bg-cyan/15 disabled:cursor-wait disabled:opacity-60"
            >
              {running ? "Running..." : "Run All Benchmarks"}
            </button>
            <button
              type="button"
              onClick={refreshLatest}
              disabled={running || loadingLatest}
              className="inline-flex items-center gap-2 rounded border border-line/45 bg-panel-strong px-3 py-2 font-mono text-xs text-text transition hover:border-cyan/50 disabled:cursor-wait disabled:opacity-60"
            >
              <RefreshCw size={14} className="text-cyan" />
              {loadingLatest ? "Refreshing..." : "Refresh Latest Results"}
            </button>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {benchmarkSteps.map((step) => (
            <span
              key={step.type}
              className="rounded border border-line/35 bg-background/45 px-3 py-1 font-mono text-xs text-muted"
            >
              {step.label}: <StatusText value={stepStatus(suite, step.type, running)} />
            </span>
          ))}
        </div>
        {error ? (
          <div className="mt-4 rounded border border-orange/35 bg-orange/10 p-3 text-sm text-orange">
            {error}
          </div>
        ) : null}
        {!running && fabricPipelineFailed ? (
          <div className="mt-4 rounded border border-danger/35 bg-danger/10 p-3 text-sm text-danger">
            {fabricPipelineStep?.error || "Fabric pipeline benchmark failed. Fabric lifecycle values are not available for this run."}
          </div>
        ) : null}
      </section>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => (
          <MetricCard key={card.label} card={card} loading={running} />
        ))}
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <ChartCard title="Centralised Baseline vs Fabric pipeline stages">
          {running ? (
            <ChartSkeleton />
          ) : stageRows.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stageRows} layout="vertical" margin={{ top: 8, right: 24, bottom: 8, left: 18 }}>
                <CartesianGrid stroke={chartPalette.grid} horizontal={false} />
                <XAxis type="number" stroke={chartPalette.muted} tickLine={false} tickFormatter={(value) => formatAxisDuration(Number(value))} />
                <YAxis type="category" dataKey="shortLabel" stroke={chartPalette.muted} tickLine={false} width={82} />
                <Tooltip content={<StageTooltip />} cursor={{ fill: chartPalette.cursor }} />
                <Bar dataKey="local" name={baselineLabel} fill={chartPalette.baseline} radius={[0, 4, 4, 0]} />
                <Bar dataKey="fabric" name="Fabric" fill={chartPalette.fabric} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyPanel message={fabricPipelineFailed ? "Fabric pipeline failed. Centralised Baseline values may still be available in the operation table." : "Run all benchmarks to populate Centralised Baseline vs Fabric stage comparison."} />
          )}
        </ChartCard>
        <ChartCard title="Fabric operation cost by category">
          {running ? (
            <ChartSkeleton />
          ) : categoryRows.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryRows} layout="vertical" margin={{ top: 8, right: 24, bottom: 8, left: 32 }}>
                <CartesianGrid stroke={chartPalette.grid} horizontal={false} />
                <XAxis type="number" stroke={chartPalette.muted} tickLine={false} tickFormatter={(value) => formatAxisDuration(Number(value))} />
                <YAxis type="category" dataKey="category" stroke={chartPalette.muted} tickLine={false} width={128} />
                <Tooltip content={<CategoryTooltip />} cursor={{ fill: chartPalette.cursor }} />
                <Bar dataKey="average" name="Average duration" radius={[0, 4, 4, 0]}>
                  {categoryRows.map((row, index) => (
                    <Cell key={row.category} fill={categoryColors[index % categoryColors.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyPanel message="Fabric category costs will appear after a benchmark suite run." />
          )}
        </ChartCard>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <TableCard title="Centralised Baseline vs Fabric operation timings">
          {running ? (
            <TableSkeleton columns={4} />
          ) : (
            <ComparisonTable
              rows={comparisonRows}
              onTooltip={showTableTooltip}
              onTooltipEnd={hideTableTooltip}
            />
          )}
        </TableCard>
        <TableCard title="Fabric ops timings">
          {running ? (
            <TableSkeleton columns={3} />
          ) : (
            <FabricOpsTable
              operations={visibleOps}
              page={opsPage}
              totalPages={totalOpsPages}
              totalRows={fabricOpsOperations.length}
              onTooltip={showTableTooltip}
              onTooltipEnd={hideTableTooltip}
              onPageChange={setOpsPage}
            />
          )}
        </TableCard>
      </div>
      <ConstrainedSection summary={constrained} loading={running} />
      <RevocationConnectivitySection
        summary={revocationConnectivity}
        loading={running}
        onTooltip={showTableTooltip}
        onTooltipEnd={hideTableTooltip}
      />
      <FabricTuningSection summary={fabricTuning} loading={running} />
      <ResourceUsageSection rows={resourceUsage} reason={resourceUsageReason} loading={running} />
      {tableTooltip ? (
        <div
          className="performance-tooltip"
          style={{ left: tableTooltip.x, top: tableTooltip.y }}
        >
          {tableTooltip.text}
        </div>
      ) : null}
    </div>
  );
}

function ConstrainedSection({
  summary,
  loading,
}: {
  summary: ConstrainedBenchmarkSummary | null;
  loading: boolean;
}) {
  const profiles = summary?.profiles || [];
  const gateway = profiles.find((profile) => profile.profile === "gateway");
  const constrained = profiles.find((profile) => profile.profile === "constrained");
  const low = profiles.find((profile) => profile.profile === "low_resource");
  const tiny = profiles.find((profile) => profile.profile === "tiny");
  return (
    <section className="glass-card rounded p-5">
      <SectionIntro
        title="Constrained device emulation"
        description="Each profile runs the holder workflow inside its own resource limited device agent container."
      />
      <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard card={{ label: "Gateway full lifecycle", value: formatDuration(gateway?.full_lifecycle_ms), color: chartPalette.fabric }} loading={loading} />
        <MetricCard card={{ label: "Constrained full lifecycle", value: formatDuration(constrained?.full_lifecycle_ms), color: chartPalette.warning }} loading={loading} />
        <MetricCard card={{ label: "Low resource full lifecycle", value: formatDuration(low?.full_lifecycle_ms), color: chartPalette.revocation }} loading={loading} />
        <MetricCard card={{ label: "Tiny IoT full lifecycle", value: formatDuration(tiny?.full_lifecycle_ms), color: chartPalette.proof }} loading={loading} />
      </div>
      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <ChartCard title="Constrained profile latency comparison">
          {loading ? (
            <ChartSkeleton />
          ) : profiles.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={profiles} margin={{ top: 8, right: 18, bottom: 8, left: 0 }}>
                <CartesianGrid stroke={chartPalette.grid} vertical={false} />
                <XAxis dataKey="label" stroke={chartPalette.muted} tickLine={false} />
                <YAxis stroke={chartPalette.muted} tickLine={false} tickFormatter={(value) => formatAxisDuration(Number(value))} />
                <Tooltip
                  formatter={(value) => formatDuration(Number(value))}
                  contentStyle={tooltipStyle}
                  labelStyle={tooltipLabelStyle}
                  cursor={{ fill: chartPalette.cursor }}
                />
                <Bar dataKey="full_lifecycle_ms" name="Full lifecycle" fill={chartPalette.fabric} radius={[4, 4, 0, 0]} />
                <Bar dataKey="auth_allow_ms" name="Valid access" fill={chartPalette.success} radius={[4, 4, 0, 0]} />
                <Bar dataKey="proof_refresh_ms" name="Proof refresh" fill={chartPalette.proof} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyPanel message="Constrained device emulation results will appear after Run All Benchmarks." />
          )}
        </ChartCard>
        <TableCard title="Docker constrained device profile timings">
          {loading ? <TableSkeleton columns={7} /> : <ConstrainedTable profiles={profiles} />}
        </TableCard>
      </div>
    </section>
  );
}

function RevocationConnectivitySection({
  summary,
  loading,
  onTooltip,
  onTooltipEnd,
}: {
  summary: RevocationConnectivitySummary | null;
  loading: boolean;
  onTooltip: (text: string | undefined, event: React.MouseEvent) => void;
  onTooltipEnd: () => void;
}) {
  const tests = (summary?.tests || []).filter((test) => !isUnsupportedRevocationTest(test));
  const metric = (name: string) => tests.find((test) => test.test === name)?.latency_ms;
  return (
    <section className="glass-card rounded p-5">
      <SectionIntro
        title="Revocation and intermittent connectivity"
        description="Tests device-agent stale proof denial, proof refresh recovery, restore access, delayed reconnect, and Docker proxy network disruption."
      />
      <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard card={{ label: "Active stale denial", value: formatDuration(metric("Active stale proof denial")), color: chartPalette.revocation }} loading={loading} />
        <MetricCard card={{ label: "Revoked stale denial", value: formatDuration(metric("Revoked stale proof denial")), color: chartPalette.danger }} loading={loading} />
        <MetricCard card={{ label: "Proof refresh", value: formatDuration(metric("Active stale proof refresh recovery")), color: chartPalette.proof }} loading={loading} />
        <MetricCard card={{ label: "Restore access", value: formatDuration(metric("Restore access recovery")), color: chartPalette.success }} loading={loading} />
      </div>
      <div className="mt-5">
        <TableCard title="Revocation connectivity test results">
          {loading ? (
            <TableSkeleton columns={7} />
          ) : (
            <RevocationTable tests={tests} onTooltip={onTooltip} onTooltipEnd={onTooltipEnd} />
          )}
        </TableCard>
      </div>
    </section>
  );
}

function FabricTuningSection({
  summary,
  loading,
}: {
  summary: FabricTuningSummary | null;
  loading: boolean;
}) {
  const profiles = summary?.profiles || [];
  const visibleProfiles = profiles.filter(isVisibleFabricTuningProfile);
  const completedProfiles = visibleProfiles.filter((profile) => profile.status === "completed");
  const pressureRows = buildWritePressureRows(visibleProfiles);
  const hasOnlyCurrentCompleted = completedProfiles.length === 1 && completedProfiles[0]?.profile_id === "current";
  return (
    <section className="glass-card rounded p-5">
      <SectionIntro
        title="Fabric tuning tests"
        description="Compares Fabric latency under different block and batching configurations."
      />
      {!loading && hasOnlyCurrentCompleted ? (
        <div className="mt-3 rounded border border-orange/35 bg-orange/10 p-3 text-sm text-orange">
          Only the current Fabric settings result is available.
        </div>
      ) : null}
      <div className="mt-5">
        <ChartCard title="Fabric tuning latency comparison">
          {loading ? (
            <ChartSkeleton />
          ) : completedProfiles.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={completedProfiles} layout="vertical" margin={{ top: 8, right: 28, bottom: 8, left: 36 }}>
                <CartesianGrid stroke={chartPalette.grid} horizontal={false} />
                <XAxis
                  type="number"
                  stroke={chartPalette.muted}
                  tickLine={false}
                  tickFormatter={(value) => formatAxisDuration(Number(value))}
                />
                <YAxis
                  type="category"
                  dataKey="profile_id"
                  stroke={chartPalette.muted}
                  tickLine={false}
                  tickFormatter={formatFabricTuningProfileName}
                  width={170}
                  tick={{ fontSize: 11 }}
                />
                <Tooltip
                  formatter={(value) => typeof value === "number" ? formatDuration(value) : value}
                  labelFormatter={(label) => formatFabricTuningProfileName(String(label))}
                  contentStyle={tooltipStyle}
                  labelStyle={tooltipLabelStyle}
                  cursor={{ fill: chartPalette.cursor }}
                />
                <Bar dataKey="full_lifecycle_ms" name="Full lifecycle" fill={chartPalette.fabric} radius={[0, 4, 4, 0]} />
                <Bar dataKey="auth_allow_ms" name="Valid access" fill={chartPalette.success} radius={[0, 4, 4, 0]} />
                <Bar dataKey="revocation_ms" name="Revocation" fill={chartPalette.revocation} radius={[0, 4, 4, 0]} />
                <Bar dataKey="proof_refresh_ms" name="Proof refresh" fill={chartPalette.proof} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyPanel message="No completed Fabric tuning profile results yet." />
          )}
        </ChartCard>
      </div>
      <div className="mt-5">
        <TableCard title="Fabric tuning profile results">
          {loading ? <TableSkeleton columns={14} /> : <FabricTuningTable profiles={visibleProfiles} />}
        </TableCard>
      </div>
      <div className="mt-6">
        <SectionIntro
          title="Fabric write pressure test"
          description="Runs 100 IAM ledger writes to compare batching behavior under heavier load."
        />
        <p className="mt-1 font-mono text-xs text-muted">
          This controlled workload stresses IAM ledger writes. It is separate from the single device lifecycle benchmark.
        </p>
        <div className="mt-5 grid gap-5 xl:grid-cols-2">
          <ChartCard title="Write throughput">
            {loading ? (
              <ChartSkeleton />
            ) : pressureRows.some((row) => row.writes_per_second !== null) ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={pressureRows} layout="vertical" margin={{ top: 8, right: 24, bottom: 8, left: 42 }}>
                  <CartesianGrid stroke={chartPalette.grid} horizontal={false} />
                  <XAxis type="number" stroke={chartPalette.muted} tickLine={false} tickFormatter={(value) => `${Number(value).toFixed(1)}/s`} />
                  <YAxis type="category" dataKey="label" stroke={chartPalette.muted} tickLine={false} width={190} tick={{ fontSize: 11 }} />
                  <Tooltip
                    formatter={(value) => `${Number(value).toFixed(3)} writes/s`}
                    contentStyle={tooltipStyle}
                    labelStyle={tooltipLabelStyle}
                    cursor={{ fill: chartPalette.cursor }}
                  />
                  <Bar dataKey="writes_per_second" name="Writes per second" fill={chartPalette.fabric} radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyPanel message="Write pressure results are not available yet." />
            )}
          </ChartCard>
          <ChartCard title="P95 write latency">
            {loading ? (
              <ChartSkeleton />
            ) : pressureRows.some((row) => row.p95_write_latency_ms !== null) ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={pressureRows} layout="vertical" margin={{ top: 8, right: 24, bottom: 8, left: 42 }}>
                  <CartesianGrid stroke={chartPalette.grid} horizontal={false} />
                  <XAxis type="number" stroke={chartPalette.muted} tickLine={false} tickFormatter={(value) => formatAxisDuration(Number(value))} />
                  <YAxis type="category" dataKey="label" stroke={chartPalette.muted} tickLine={false} width={190} tick={{ fontSize: 11 }} />
                  <Tooltip
                    formatter={(value) => formatDuration(Number(value))}
                    contentStyle={tooltipStyle}
                    labelStyle={tooltipLabelStyle}
                    cursor={{ fill: chartPalette.cursor }}
                  />
                  <Bar dataKey="p95_write_latency_ms" name="P95 write latency" fill={chartPalette.revocation} radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyPanel message="Write pressure latency is not available yet." />
            )}
          </ChartCard>
        </div>
        <div className="mt-5">
          {loading ? <TableSkeleton columns={10} /> : <FabricWritePressureTable rows={pressureRows} />}
        </div>
      </div>
    </section>
  );
}

function ResourceUsageSection({
  rows,
  reason,
  loading,
}: {
  rows: ResourceUsageRow[];
  reason: string | null;
  loading: boolean;
}) {
  const compactRows = aggregateResourceUsageRows(rows);
  return (
    <section className="glass-card rounded p-5">
      <SectionIntro
        title="Runtime resource footprint"
        description="CPU and memory usage observed during benchmark execution."
      />
      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <ChartCard title="Peak memory by service">
          {loading ? (
            <ChartSkeleton />
          ) : compactRows.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={compactRows} layout="vertical" margin={{ top: 8, right: 24, bottom: 8, left: 12 }}>
                <CartesianGrid stroke={chartPalette.grid} horizontal={false} />
                <XAxis
                  type="number"
                  stroke={chartPalette.muted}
                  tickLine={false}
                  domain={[0, resourceAxisMax]}
                  allowDecimals={false}
                  tickCount={5}
                  tickFormatter={formatMemoryAxisTick}
                />
                <YAxis
                  type="category"
                  dataKey="service"
                  stroke={chartPalette.muted}
                  tickLine={false}
                  width={178}
                  tick={{ fontSize: 11 }}
                  tickFormatter={formatChartServiceName}
                />
                <Tooltip
                  formatter={(value) => `${Number(value).toFixed(1)} MB`}
                  labelFormatter={(label) => formatServiceName(String(label))}
                  contentStyle={tooltipStyle}
                  labelStyle={tooltipLabelStyle}
                  cursor={{ fill: chartPalette.cursor }}
                />
                <Bar dataKey="peak_memory_mb" name="Peak RAM" fill={chartPalette.fabric} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyPanel message={reason || "Resource usage not available for this run."} />
          )}
        </ChartCard>
        <ChartCard title="Average CPU by service">
          {loading ? (
            <ChartSkeleton />
          ) : compactRows.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={compactRows} layout="vertical" margin={{ top: 8, right: 24, bottom: 8, left: 12 }}>
                <CartesianGrid stroke={chartPalette.grid} horizontal={false} />
                <XAxis
                  type="number"
                  stroke={chartPalette.muted}
                  tickLine={false}
                  domain={[0, resourceAxisMax]}
                  allowDecimals={false}
                  tickCount={5}
                  tickFormatter={formatPercentAxisTick}
                />
                <YAxis
                  type="category"
                  dataKey="service"
                  stroke={chartPalette.muted}
                  tickLine={false}
                  width={178}
                  tick={{ fontSize: 11 }}
                  tickFormatter={formatChartServiceName}
                />
                <Tooltip
                  formatter={(value) => `${Number(value).toFixed(1)}%`}
                  labelFormatter={(label) => formatServiceName(String(label))}
                  contentStyle={tooltipStyle}
                  labelStyle={tooltipLabelStyle}
                  cursor={{ fill: chartPalette.cursor }}
                />
                <Bar dataKey="avg_cpu_percent" name="Average CPU" fill={chartPalette.success} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyPanel message={reason || "Resource usage not available for this run."} />
          )}
        </ChartCard>
      </div>
      <div className="mt-5">
        {loading ? <TableSkeleton columns={6} /> : <ResourceUsageTable rows={compactRows} reason={reason} />}
      </div>
    </section>
  );
}

function SectionIntro({ title, description }: { title: string; description: string }) {
  return (
    <div>
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-1 font-mono text-xs text-muted">{description}</p>
    </div>
  );
}

function MetricCard({ card, loading }: { card: MetricCardData; loading: boolean }) {
  return (
    <section className="glass-card rounded p-4">
      <div className="font-mono text-[10px] uppercase text-muted">{card.label}</div>
      {loading ? (
        <div className="skeleton-line mt-3 h-7 w-28" />
      ) : (
        <div className="mt-2 text-2xl font-bold" style={{ color: card.color }}>
          {card.value}
        </div>
      )}
    </section>
  );
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="glass-card rounded p-5">
      <h4 className="mb-4 font-semibold">{title}</h4>
      <div className="h-[320px]">{children}</div>
    </section>
  );
}

function TableCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="glass-card rounded p-5">
      <h4 className="mb-4 font-semibold">{title}</h4>
      {children}
    </section>
  );
}

function ConstrainedTable({ profiles }: { profiles: ConstrainedBenchmarkSummary["profiles"] }) {
  if (!profiles.length) return <EmptyPanel message="No constrained device emulation results yet." />;
  return (
    <div className="overflow-x-auto rounded border border-line/30 bg-background/45">
      <table className="ledger-table min-w-[720px] text-left text-xs">
        <thead className="font-mono uppercase">
          <tr>
            <HeaderCell>Profile</HeaderCell>
            <HeaderCell>CPU Limit</HeaderCell>
            <HeaderCell>Memory Limit</HeaderCell>
            <HeaderCell>Full Lifecycle</HeaderCell>
            <HeaderCell>Valid Access</HeaderCell>
            <HeaderCell>Proof Refresh</HeaderCell>
            <HeaderCell>Payload Size</HeaderCell>
          </tr>
        </thead>
        <tbody>
          {profiles.map((profile) => (
            <tr key={profile.profile} className="border-b border-line/20 last:border-0">
              <BodyCell>{profile.label}</BodyCell>
              <BodyCell mono>{profile.cpu_limit}</BodyCell>
              <BodyCell mono>{profile.memory_limit}</BodyCell>
              <BodyCell mono>{formatDuration(profile.full_lifecycle_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.auth_allow_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.proof_refresh_ms)}</BodyCell>
              <BodyCell mono>{formatBytes(profile.payload_size_bytes)}</BodyCell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function isUnsupportedRevocationTest(test: RevocationConnectivitySummary["tests"][number]) {
  const values = [test.status, test.actual, test.expected].map((value) => String(value || "").replace("-", "_").toLowerCase());
  return values.includes("not_supported");
}

function RevocationTable({
  tests,
  onTooltip,
  onTooltipEnd,
}: {
  tests: RevocationConnectivitySummary["tests"];
  onTooltip: (text: string | undefined, event: React.MouseEvent) => void;
  onTooltipEnd: () => void;
}) {
  if (!tests.length) return <EmptyPanel message="No revocation connectivity results yet." />;
  return (
    <div className="rounded border border-line/30 bg-background/45">
      <table className="ledger-table w-full table-fixed text-left text-xs">
        <thead className="font-mono uppercase">
          <tr>
            <HeaderCell className="w-[22%]">Test</HeaderCell>
            <HeaderCell className="w-[11%]">Actor</HeaderCell>
            <HeaderCell className="w-[9%]">Expected</HeaderCell>
            <HeaderCell className="w-[9%]">Actual</HeaderCell>
            <HeaderCell className="w-[29%]">Reason</HeaderCell>
            <HeaderCell className="w-[10%]">Latency</HeaderCell>
            <HeaderCell className="w-[10%]">Status</HeaderCell>
          </tr>
        </thead>
        <tbody>
          {tests.map((test) => (
            <tr
              key={test.test}
              onMouseEnter={(event) => onTooltip(revocationTestDetails[test.test], event)}
              onMouseMove={(event) => onTooltip(revocationTestDetails[test.test], event)}
              onMouseLeave={onTooltipEnd}
              className="border-b border-line/20 last:border-0"
            >
              <BodyCell>{test.test}</BodyCell>
              <BodyCell>{test.actor || "Device agent"}</BodyCell>
              <BodyCell mono><RevocationTerm value={test.expected} /></BodyCell>
              <BodyCell mono><RevocationTerm value={test.actual} /></BodyCell>
              <BodyCell><RevocationReason reason={test.reason || "Not available"} /></BodyCell>
              <BodyCell mono>{formatDuration(test.latency_ms)}</BodyCell>
              <BodyCell><StatusBadge status={test.status} /></BodyCell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RevocationTerm({ value }: { value: string }) {
  return <span className={revocationTermClass(value)}>{value}</span>;
}

function RevocationReason({ reason }: { reason: string }) {
  return <span className={revocationReasonClass(reason)}>{reason}</span>;
}

function revocationTermClass(value: string) {
  const normalized = value.toLowerCase().replace("-", "_");
  if (normalized === "allow" || normalized === "authorized" || normalized === "pass") return "text-green";
  if (normalized === "deny" || normalized === "denied" || normalized === "fail") return "text-danger";
  if (normalized === "blocked") return "text-orange";
  if (normalized === "not_supported" || normalized === "not supported") return "text-muted";
  return "text-cyan";
}

function revocationReasonClass(reason: string) {
  const normalized = reason.toLowerCase();
  if (normalized.includes("authorized")) return "text-green";
  if (normalized.includes("credential revoked in accumulator")) return "text-danger";
  if (normalized.includes("accumulator proof stale") || normalized.includes("blocked")) return "text-orange";
  if (normalized.includes("not supported") || normalized.includes("not_supported")) return "text-muted";
  return "text-text";
}

function FabricTuningTable({ profiles }: { profiles: FabricTuningSummary["profiles"] }) {
  if (!profiles.length) return <EmptyPanel message="No Fabric tuning results yet." />;
  return (
    <div className="overflow-x-auto rounded border border-line/30 bg-background/45">
      <table className="ledger-table min-w-[1420px] text-left text-xs">
        <thead className="font-mono uppercase">
          <tr>
            <HeaderCell>Profile</HeaderCell>
            <HeaderCell>Block Size</HeaderCell>
            <HeaderCell>Batch Timeout</HeaderCell>
            <HeaderCell>Endorsement Policy</HeaderCell>
            <HeaderCell>Full Lifecycle</HeaderCell>
            <HeaderCell>Valid Access</HeaderCell>
            <HeaderCell>Revocation</HeaderCell>
            <HeaderCell>Proof Refresh</HeaderCell>
            <HeaderCell>Ledger Read</HeaderCell>
            <HeaderCell>Ledger Write</HeaderCell>
            <HeaderCell>Read p95</HeaderCell>
            <HeaderCell>Write p95</HeaderCell>
            <HeaderCell>Read TPS</HeaderCell>
            <HeaderCell>Write TPS</HeaderCell>
            <HeaderCell>Status</HeaderCell>
          </tr>
        </thead>
        <tbody>
          {profiles.map((profile) => (
            <tr key={profile.profile_id} className="border-b border-line/20 last:border-0">
              <BodyCell>{formatFabricTuningProfileName(profile.profile_id)}</BodyCell>
              <BodyCell>{formatFabricBlockSize(profile)}</BodyCell>
              <BodyCell>{formatFabricBatchTimeout(profile)}</BodyCell>
              <BodyCell>{formatFabricEndorsement(profile)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.full_lifecycle_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.auth_allow_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.revocation_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.proof_refresh_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.ledger_read_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.ledger_write_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.read_p95_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(profile.write_p95_ms)}</BodyCell>
              <BodyCell mono>{formatNumber(fabricReadTps(profile))}</BodyCell>
              <BodyCell mono>{formatNumber(fabricWriteTps(profile))}</BodyCell>
              <BodyCell><StatusBadge status={profile.status} /></BodyCell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FabricWritePressureTable({ rows }: { rows: WritePressureRow[] }) {
  if (!rows.length) return <EmptyPanel message="Write pressure results are not available yet." />;
  return (
    <div className="overflow-x-auto rounded border border-line/30 bg-background/45">
      <table className="ledger-table min-w-[1220px] text-left text-xs">
        <thead className="font-mono uppercase">
          <tr>
            <HeaderCell className="w-[22%]">Profile</HeaderCell>
            <HeaderCell className="w-[8%]">Total writes</HeaderCell>
            <HeaderCell className="w-[9%]">Successful writes</HeaderCell>
            <HeaderCell className="w-[8%]">Failed writes</HeaderCell>
            <HeaderCell className="w-[11%]">Average write latency</HeaderCell>
            <HeaderCell className="w-[10%]">P50 write latency</HeaderCell>
            <HeaderCell className="w-[10%]">P95 write latency</HeaderCell>
            <HeaderCell className="w-[9%]">Writes per second</HeaderCell>
            <HeaderCell className="w-[8%]">Slowest write</HeaderCell>
            <HeaderCell className="whitespace-nowrap">Status</HeaderCell>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.profile_id} className="border-b border-line/20 last:border-0">
              <BodyCell>
                <div>{row.label}</div>
                {row.groups?.length ? (
                  <details className="mt-1 text-[11px] text-muted">
                    <summary className="cursor-pointer font-mono uppercase">Group details</summary>
                    <div className="mt-1 space-y-1">
                      {row.groups.map((group) => (
                        <div key={group.operation_type}>
                          {formatPressureGroupName(group.operation_type)}: {formatNumber(group.successful_writes)} ok,
                          {" "}{formatNumber(group.failures)} failed, p95 {formatDuration(group.p95_latency_ms)}
                        </div>
                      ))}
                    </div>
                  </details>
                ) : null}
              </BodyCell>
              <BodyCell mono>{formatNumber(row.total_writes)}</BodyCell>
              <BodyCell mono>{formatNumber(row.successful_writes)}</BodyCell>
              <BodyCell mono>{formatNumber(row.failed_writes)}</BodyCell>
              <BodyCell mono>{formatDuration(row.average_write_latency_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(row.p50_write_latency_ms)}</BodyCell>
              <BodyCell mono>{formatDuration(row.p95_write_latency_ms)}</BodyCell>
              <BodyCell mono>{formatNumber(row.writes_per_second)}</BodyCell>
              <BodyCell mono>{formatDuration(row.max_write_latency_ms)}</BodyCell>
              <BodyCell className="whitespace-nowrap"><StatusBadge status={row.status} /></BodyCell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ResourceUsageTable({ rows, reason }: { rows: AggregatedResourceUsageRow[]; reason: string | null }) {
  if (!rows.length) return <EmptyPanel message={reason || "Resource usage not available for this run."} />;
  return (
    <div className="rounded border border-line/30 bg-background/45">
      <table className="ledger-table w-full table-fixed text-left text-xs">
        <thead className="font-mono uppercase">
          <tr>
            <HeaderCell className="w-[30%]">Service</HeaderCell>
            <HeaderCell className="w-[14%]">Average CPU</HeaderCell>
            <HeaderCell className="w-[14%]">Peak CPU</HeaderCell>
            <HeaderCell className="w-[16%]">Average RAM</HeaderCell>
            <HeaderCell className="w-[16%]">Peak RAM</HeaderCell>
            <HeaderCell className="w-[10%]">Samples</HeaderCell>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.service} className="border-b border-line/20 last:border-0">
              <BodyCell>{formatServiceName(row.service)}</BodyCell>
              <BodyCell mono>{formatPercent(row.avg_cpu_percent)}</BodyCell>
              <BodyCell mono>{formatPercent(row.peak_cpu_percent)}</BodyCell>
              <BodyCell mono>{formatMemory(row.avg_memory_mb)}</BodyCell>
              <BodyCell mono>{formatMemory(row.peak_memory_mb)}</BodyCell>
              <BodyCell mono>{formatNumber(row.sample_count)}</BodyCell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  const good = normalized === "pass" || normalized === "completed";
  const warn =
    normalized === "completed_with_failures" ||
    normalized === "completed with failures" ||
    normalized === "not_run" ||
    normalized === "not run" ||
    normalized === "not_available" ||
    normalized === "not available" ||
    normalized === "not_supported" ||
    normalized === "not-supported" ||
    normalized === "not supported";
  return (
    <span className={`whitespace-nowrap rounded border px-2 py-1 font-mono text-[10px] uppercase ${
      good
        ? "border-green/40 bg-green/10 text-green"
        : warn
          ? "border-line/40 bg-background/50 text-muted"
          : "border-danger/40 bg-danger/10 text-danger"
    }`}>
      {formatStatusLabel(status)}
    </span>
  );
}

function formatStatusLabel(status: string): string {
  const normalized = status.toLowerCase().replace(/[-_]+/g, " ");
  const labels: Record<string, string> = {
    completed: "Completed",
    "completed with failures": "Completed with failures",
    failed: "Failed",
    "not available": "Not available",
    "not supported": "Not supported",
    "not run": "Not run",
  };
  return labels[normalized] || normalized || "Unknown";
}

function ChartSkeleton() {
  return (
    <div className="skeleton-card flex h-full flex-col justify-center gap-4 p-5">
      {[78, 64, 88, 52, 72].map((width, index) => (
        <div key={index} className="flex items-center gap-3">
          <div className="skeleton-line h-3 w-28" />
          <div className="skeleton-line h-5" style={{ width: `${width}%` }} />
        </div>
      ))}
    </div>
  );
}

function EmptyPanel({ message }: { message: string }) {
  return <div className="rounded border border-line/35 bg-background/45 p-4 text-muted">{message}</div>;
}

function TableSkeleton({ columns }: { columns: number }) {
  return (
    <div className="skeleton-card p-4">
      {Array.from({ length: 6 }).map((_, rowIndex) => (
        <div key={rowIndex} className="mb-3 grid gap-3 last:mb-0" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
          {Array.from({ length: columns }).map((__, columnIndex) => (
            <div key={columnIndex} className="skeleton-line h-4" />
          ))}
        </div>
      ))}
    </div>
  );
}

function StatusText({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const color =
    normalized === "completed"
      ? "text-green"
      : normalized === "completed_with_errors"
        ? "text-orange"
      : normalized === "failed"
        ? "text-danger"
        : normalized === "running"
          ? "text-cyan"
          : "text-muted";
  return <span className={color}>{capitalize(value)}</span>;
}

function CategoryTooltip({ active, payload, label }: TooltipProps) {
  if (!active || !payload?.length) return null;
  const row = payload[0]?.payload as CategoryRow | undefined;
  const category = row?.category || String(label || "");
  return (
    <div style={tooltipStyle}>
      <div className="font-semibold text-text">{category}</div>
      <div className="mt-1 font-mono text-xs text-cyan">Average: {formatDuration(row?.average)}</div>
      <div className="mt-1 text-xs text-muted">{row?.count || 0} operation{row?.count === 1 ? "" : "s"}</div>
      <div className="mt-1 font-mono text-xs text-orange">Slowest: {row?.slowestLabel || "Not available"} ({formatDuration(row?.max)})</div>
      <div className="mt-2 max-w-[280px] text-xs text-muted">{categoryDetails[category] || "Fabric ledger operation category."}</div>
    </div>
  );
}

function StageTooltip({ active, payload, label }: TooltipProps) {
  if (!active || !payload?.length) return null;
  const row = payload[0]?.payload as StageRow | undefined;
  return (
    <div style={tooltipStyle}>
      <div className="font-semibold text-text">{row?.label || label}</div>
      {payload.map((item) => (
        <div key={String(item.name)} className="mt-1 font-mono text-xs" style={{ color: item.color }}>
          {item.name}: {formatDuration(Number(item.value))}
        </div>
      ))}
      <div className="mt-2 max-w-[260px] text-xs text-muted">{row?.includes}</div>
    </div>
  );
}

function ComparisonTable({
  rows,
  onTooltip,
  onTooltipEnd,
}: {
  rows: ComparisonRow[];
  onTooltip: (text: string | undefined, event: React.MouseEvent) => void;
  onTooltipEnd: () => void;
}) {
  if (!rows.length) return <EmptyPanel message="Run all benchmarks to populate operation timings." />;
  return (
    <div className="rounded border border-line/30 bg-background/45">
      <table className="ledger-table w-full table-fixed text-left text-xs">
        <thead className="font-mono uppercase">
          <tr>
            <HeaderCell className="w-[44%]">Operation</HeaderCell>
            <HeaderCell className="w-[17%]">Centralised Baseline</HeaderCell>
            <HeaderCell className="w-[17%]">Fabric</HeaderCell>
            <HeaderCell className="w-[22%]">Difference</HeaderCell>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.key}
              onMouseEnter={(event) => onTooltip(row.detail, event)}
              onMouseMove={(event) => onTooltip(row.detail, event)}
              onMouseLeave={onTooltipEnd}
              className="border-b border-line/20 last:border-0"
            >
              <BodyCell>{row.operation}</BodyCell>
              <BodyCell mono>{formatDuration(row.local)}</BodyCell>
              <BodyCell mono>{formatCollectedDuration(row.fabric)}</BodyCell>
              <BodyCell mono tone={row.difference !== null && row.difference !== undefined && row.difference <= 0 ? "good" : "warn"}>
                {formatDifference(row.difference)}
              </BodyCell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FabricOpsTable({
  operations,
  page,
  totalPages,
  totalRows,
  onTooltip,
  onTooltipEnd,
  onPageChange,
}: {
  operations: BenchmarkOperation[];
  page: number;
  totalPages: number;
  totalRows: number;
  onTooltip: (text: string | undefined, event: React.MouseEvent) => void;
  onTooltipEnd: () => void;
  onPageChange: (page: number) => void;
}) {
  if (!operations.length) return <EmptyPanel message="Fabric ops timings will appear after a benchmark suite run." />;
  return (
    <div>
      {totalRows > 15 ? (
        <div className="mb-3 flex items-center justify-end gap-2 font-mono text-xs text-muted">
          <button type="button" onClick={() => onPageChange(Math.max(1, page - 1))} disabled={page <= 1} className="rounded border border-line/40 bg-panel px-3 py-1 text-text disabled:cursor-not-allowed disabled:opacity-40">
            Previous
          </button>
          <span>Page {page} of {totalPages}</span>
          <button type="button" onClick={() => onPageChange(Math.min(totalPages, page + 1))} disabled={page >= totalPages} className="rounded border border-line/40 bg-panel px-3 py-1 text-text disabled:cursor-not-allowed disabled:opacity-40">
            Next
          </button>
        </div>
      ) : null}
      <div className="rounded border border-line/30 bg-background/45">
        <table className="ledger-table w-full table-fixed text-left text-xs">
          <thead className="font-mono uppercase">
            <tr>
              <HeaderCell className="w-[52%]">Operation</HeaderCell>
              <HeaderCell className="w-[22%]">Duration</HeaderCell>
              <HeaderCell className="w-[26%]">Category</HeaderCell>
            </tr>
          </thead>
          <tbody>
            {operations.map((operation) => (
              <tr
                key={operation.key}
                onMouseEnter={(event) => onTooltip(fabricOpsDetails[operation.key] || operation.notes, event)}
                onMouseMove={(event) => onTooltip(fabricOpsDetails[operation.key] || operation.notes, event)}
                onMouseLeave={onTooltipEnd}
                className="border-b border-line/20 last:border-0"
              >
                <BodyCell>{operation.label}</BodyCell>
                <BodyCell mono>{formatDuration(operation.duration_ms)}</BodyCell>
                <BodyCell>{operation.category}</BodyCell>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function HeaderCell({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <th className={`px-3 py-2 text-[10px] font-semibold ${className}`}>{children}</th>;
}

function BodyCell({
  children,
  mono = false,
  tone,
  className = "",
}: {
  children: React.ReactNode;
  mono?: boolean;
  tone?: "good" | "warn";
  className?: string;
}) {
  const toneClass = tone === "good" ? "text-green" : tone === "warn" ? "text-orange" : "text-cyan";
  return <td className={`break-words px-3 py-2 align-top text-text ${mono ? `font-mono ${toneClass}` : ""} ${className}`}>{children}</td>;
}

type MetricCardData = {
  label: string;
  value: string;
  color: string;
};

type ComparisonRow = {
  key: string;
  operation: string;
  local?: number | null;
  fabric?: number | null;
  difference?: number | null;
  detail: string;
};

type StageRow = {
  key: string;
  shortLabel: string;
  label: string;
  local?: number | null;
  fabric?: number | null;
  includes: string;
};

type CategoryRow = {
  category: string;
  average: number;
  max: number;
  slowestLabel: string;
  count: number;
};

type AggregatedResourceUsageRow = {
  service: string;
  avg_cpu_percent: number | null;
  peak_cpu_percent: number | null;
  avg_memory_mb: number | null;
  peak_memory_mb: number | null;
  sample_count: number | null;
};

type WritePressureRow = {
  profile_id: string;
  label: string;
  status: string;
  total_writes: number | null;
  successful_writes: number | null;
  failed_writes: number | null;
  average_write_latency_ms: number | null;
  p50_write_latency_ms: number | null;
  p95_write_latency_ms: number | null;
  max_write_latency_ms: number | null;
  writes_per_second: number | null;
  groups: NonNullable<FabricTuningSummary["profiles"][number]["write_pressure"]>["groups"];
};

type TooltipProps = {
  active?: boolean;
  label?: string;
  payload?: Array<{
    name?: string;
    value?: number | string;
    color?: string;
    payload?: unknown;
  }>;
};

type TableTooltipState = {
  text: string;
  x: number;
  y: number;
};

function buildComparisonRows(summary: BenchmarkSuite["combined_summary"] | null): ComparisonRow[] {
  const localOps = operationMap(summary?.comparison.local);
  const fabricOps = operationMap(summary?.comparison.fabric);
  return comparisonOrder
    .map((key) => {
      const local = localOps.get(key);
      const fabric = fabricOps.get(key);
      const label = fabric?.label || local?.label || key.replace(/_/g, " ");
      return {
        key,
        operation: label,
        local: local?.duration_ms ?? null,
        fabric: fabric?.duration_ms ?? null,
        difference:
          local?.duration_ms !== undefined && fabric?.duration_ms !== undefined
            ? fabric.duration_ms - local.duration_ms
            : null,
        detail: operationDetails[key] || "Benchmark operation timing.",
      };
    })
    .filter((row) => row.local !== null || row.fabric !== null);
}

function buildStageRows(summary: BenchmarkSuite["combined_summary"] | null): StageRow[] {
  const localOps = operationMap(summary?.comparison.local);
  const fabricOps = operationMap(summary?.comparison.fabric);
  return pipelineStages
    .map((stage) => ({
      key: stage.key,
      shortLabel: stage.shortLabel,
      label: stage.label,
      local: stageTotal(localOps, stage.operationKeys),
      fabric: stageTotal(fabricOps, stage.operationKeys),
      includes: stage.includes,
    }))
    .filter((row) => row.local !== null || row.fabric !== null);
}

function stageTotal(ops: Map<string, BenchmarkOperation>, keys: string[]): number | null {
  const values = keys
    .map((key) => ops.get(key)?.duration_ms)
    .filter((value): value is number => value !== undefined && value !== null);
  if (!values.length) return null;
  return values.reduce((sum, value) => sum + value, 0);
}

function operationMap(entry?: BenchmarkComparisonEntry | null): Map<string, BenchmarkOperation> {
  return new Map((entry?.operations || []).map((operation) => [operation.key, operation]));
}

function buildWritePressureRows(profiles: FabricTuningSummary["profiles"]): WritePressureRow[] {
  return profiles.map((profile) => {
    const pressure = profile.write_pressure || null;
    return {
      profile_id: profile.profile_id,
      label: formatFabricTuningProfileName(profile.profile_id),
      status: pressure?.status || "not_available",
      total_writes: pressure?.total_writes ?? null,
      successful_writes: pressure?.successful_writes ?? null,
      failed_writes: pressure?.failed_writes ?? null,
      average_write_latency_ms: pressure?.average_write_latency_ms ?? null,
      p50_write_latency_ms: pressure?.p50_write_latency_ms ?? null,
      p95_write_latency_ms: pressure?.p95_write_latency_ms ?? null,
      max_write_latency_ms: pressure?.max_write_latency_ms ?? null,
      writes_per_second: pressure?.writes_per_second ?? null,
      groups: pressure?.groups || [],
    };
  });
}

function formatPressureGroupName(operationType: string): string {
  const names: Record<string, string> = {
    did_registry: "DID registry",
    credential_status: "Credential status",
    accumulator_state: "Accumulator state",
    audit_event: "Audit event",
  };
  return names[operationType] || toTitleCase(operationType);
}

function isVisibleFabricTuningProfile(profile: FabricTuningSummary["profiles"][number]): boolean {
  return profile.profile_id !== "light_endorsement" || profile.status === "completed";
}

function formatFabricTuningProfileName(profileId: string): string {
  const names: Record<string, string> = {
    current: "Original Fabric baseline",
    low_latency: "Fast block commit",
    fast_block_commit: "Fast block commit",
    larger_batch: "Main tuned Fabric settings",
    larger_batch_window: "Main tuned Fabric settings",
    light_endorsement: "Light endorsement policy",
  };
  return names[profileId] || toTitleCase(profileId);
}

function formatFabricBlockSize(profile: FabricTuningSummary["profiles"][number]): string {
  const profileValues: Record<string, string> = {
    current: "Max message count: 10, preferred max bytes: 512 KB, absolute max bytes: 99 MB",
    low_latency: "Max message count: 5, preferred max bytes: 512 KB, absolute max bytes: 10 MB",
    fast_block_commit: "Max message count: 5, preferred max bytes: 512 KB, absolute max bytes: 10 MB",
    larger_batch: "Max message count: 50, preferred max bytes: 2 MB, absolute max bytes: 10 MB",
    larger_batch_window: "Max message count: 50, preferred max bytes: 2 MB, absolute max bytes: 10 MB",
  };
  if (profileValues[profile.profile_id]) return profileValues[profile.profile_id];
  const value = profile.block_size || "";
  if (value === "current") return profileValues.current;
  if (value === "small") return "Max message count: 5";
  if (value === "large") return "Max message count: 50";
  return value || "Not available";
}

function formatFabricBatchTimeout(profile: FabricTuningSummary["profiles"][number]): string {
  const value = profile.batch_timeout || "";
  if (profile.profile_id === "current" || value === "current") return "2 seconds";
  if (value === "500ms") return "0.5 seconds";
  if (value === "2s") return "2 seconds";
  return value || "Not available";
}

function formatFabricEndorsement(profile: FabricTuningSummary["profiles"][number]): string {
  const value = profile.endorsement_policy || "";
  if (profile.profile_id === "current" || value === "current") {
    return "Default Fabric test-network chaincode policy; requests target Org1 and Org2 peers";
  }
  if (value === "lighter") return "Lighter endorsement policy";
  if (value === "not_applicable") return "Not applied";
  return value || "Not available";
}

function fabricReadTps(profile: FabricTuningSummary["profiles"][number]): number | null {
  return profile.read_tps ?? throughputFromDuration(profile.ledger_read_ms);
}

function fabricWriteTps(profile: FabricTuningSummary["profiles"][number]): number | null {
  return profile.write_tps ?? throughputFromDuration(profile.ledger_write_ms);
}

function throughputFromDuration(durationMs: number | null | undefined): number | null {
  if (durationMs === null || durationMs === undefined || Number.isNaN(durationMs) || durationMs <= 0) return null;
  return 1000 / durationMs;
}

function formatServiceName(service: string): string {
  return resourceServiceNames[service] || toTitleCase(service);
}

function formatChartServiceName(service: string): string {
  return resourceChartServiceNames[service] || formatServiceName(service);
}

function toTitleCase(value: string): string {
  return value
    .replace(/[_.-]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function buildFabricCategoryRows(operations: BenchmarkOperation[]): CategoryRow[] {
  const categories = new Map<string, BenchmarkOperation[]>();
  operations.forEach((operation) => {
    if (!categories.has(operation.category)) categories.set(operation.category, []);
    categories.get(operation.category)?.push(operation);
  });

  return Array.from(categories.entries())
    .map(([category, items]) => {
      const durations = items.map((item) => item.duration_ms).filter((value) => Number.isFinite(value));
      const total = durations.reduce((sum, value) => sum + value, 0);
      const slowest = items.reduce((max, item) => (item.duration_ms > max.duration_ms ? item : max), items[0]);
      return {
        category,
        average: durations.length ? total / durations.length : 0,
        max: slowest?.duration_ms || 0,
        slowestLabel: slowest?.label || "Not available",
        count: items.length,
      };
    })
    .sort((a, b) => b.average - a.average);
}

function aggregateResourceUsageRows(rows: ResourceUsageRow[]): AggregatedResourceUsageRow[] {
  const grouped = new Map<string, ResourceUsageRow[]>();
  rows.forEach((row) => {
    if (!resourceServiceOrder.includes(row.service)) return;
    if (!grouped.has(row.service)) grouped.set(row.service, []);
    grouped.get(row.service)?.push(row);
  });
  const aggregated: Array<AggregatedResourceUsageRow | null> = resourceServiceOrder
    .map((service) => {
      const serviceRows = grouped.get(service) || [];
      if (!serviceRows.length) return null;
      const sampleCount = serviceRows.reduce((sum, row) => sum + numericValue(row.sample_count), 0);
      return {
        service,
        avg_cpu_percent: weightedAverage(serviceRows, "avg_cpu_percent"),
        peak_cpu_percent: maxMetric(serviceRows, "peak_cpu_percent"),
        avg_memory_mb: weightedAverage(serviceRows, "avg_memory_mb"),
        peak_memory_mb: maxMetric(serviceRows, "peak_memory_mb"),
        sample_count: sampleCount || null,
      };
    });
  return aggregated.filter((row): row is AggregatedResourceUsageRow => row !== null);
}

function weightedAverage(rows: ResourceUsageRow[], key: keyof ResourceUsageRow): number | null {
  let weightedSum = 0;
  let weightTotal = 0;
  rows.forEach((row) => {
    const value = row[key];
    if (typeof value !== "number" || Number.isNaN(value)) return;
    const weight = numericValue(row.sample_count) || 1;
    weightedSum += value * weight;
    weightTotal += weight;
  });
  return weightTotal ? roundMetric(weightedSum / weightTotal) : null;
}

function maxMetric(rows: ResourceUsageRow[], key: keyof ResourceUsageRow): number | null {
  const values = rows
    .map((row) => row[key])
    .filter((value): value is number => typeof value === "number" && !Number.isNaN(value));
  return values.length ? roundMetric(Math.max(...values)) : null;
}

function numericValue(value: number | null | undefined) {
  return typeof value === "number" && !Number.isNaN(value) ? value : 0;
}

function roundMetric(value: number) {
  return Math.round(value * 1000) / 1000;
}

function stepStatus(suite: BenchmarkSuite | null, benchmarkType: string, running: boolean): string {
  const step = suite?.steps.find((item) => item.benchmark_type === benchmarkType);
  if (step?.status) return step.status;
  if (!running) return "not_run";
  if (suite?.current_step === benchmarkType) return "running";
  return "pending";
}

function formatDuration(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Not available";
  const abs = Math.abs(value);
  if (abs >= 1000) return `${(abs / 1000).toFixed(2)} s`;
  if (abs > 0 && abs < 1) return "<1 ms";
  return `${Math.round(abs)} ms`;
}

function formatCollectedDuration(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Not collected";
  return formatDuration(value);
}

function formatAxisDuration(value: number): string {
  if (value >= 1000) return `${(value / 1000).toFixed(1)}s`;
  if (value > 0 && value < 1) return "<1ms";
  return `${Math.round(value)}ms`;
}

function formatDifference(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Not available";
  const sign = value > 0 ? "+" : value < 0 ? "-" : "";
  return `${sign}${formatDuration(value)}`;
}

function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Not available";
  return `${value.toFixed(1)}%`;
}

function formatMemory(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Not available";
  return `${value.toFixed(1)} MB`;
}

function formatMemoryAxisTick(value: unknown): string {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${Math.round(numeric)} MB` : "";
}

function formatPercentAxisTick(value: unknown): string {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${Math.round(numeric)}%` : "";
}

function resourceAxisMax(dataMax: number): number {
  if (!Number.isFinite(dataMax) || dataMax <= 0) return 1;
  return dataMax * 1.18;
}

function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Not available";
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${Math.round(value)} B`;
}

function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Not available";
  return value.toFixed(2);
}

function formatLifecycleDifference(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Not available";
  if (value === 0) return "No overhead";
  if (value < 0) return `Fabric faster by ${formatDuration(value)}`;
  return `Fabric adds ${formatDuration(value)}`;
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "recently";
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

function capitalize(value: string): string {
  if (!value) return "Unknown";
  return value.slice(0, 1).toUpperCase() + value.slice(1).toLowerCase();
}

const tooltipStyle: CSSProperties = {
  background: chartPalette.tooltipBackground,
  border: `1px solid ${chartPalette.tooltipBorder}`,
  color: chartPalette.text,
  borderRadius: "6px",
  padding: "10px 12px",
};

const tooltipLabelStyle: CSSProperties = {
  color: chartPalette.text,
  fontWeight: 600,
};
