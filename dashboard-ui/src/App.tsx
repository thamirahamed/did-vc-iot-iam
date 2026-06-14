import { useCallback, useEffect, useMemo, useState } from "react";
import {
  authorizeDevice,
  cleanDashboardState,
  createDashboardDevice,
  errorMessage,
  getAccumulatorState,
  getAuditEvents,
  getDashboardDevices,
  getDeviceAuditEvents,
  getLedgerSummary,
  getScenarioResults,
  issueCapabilityForDevice,
  issueIdentityForDevice,
  refreshProofForDevice,
  restoreDeviceAccess,
  revokeDeviceCapability,
  runSecurityScenario,
  serviceHealthFromLedgerSummary,
} from "./api/client";
import AuditTimeline from "./components/AuditTimeline";
import DeviceWalletPage from "./components/DeviceWalletPage";
import FabricLedgerPage from "./components/FabricLedgerPage";
import Layout from "./components/Layout";
import PerformancePage from "./components/PerformancePage";
import SecurityScenariosPage from "./components/SecurityScenariosPage";
import TopologyPage from "./components/TopologyPage";
import type {
  ActionResult,
  AccumulatorState,
  AuditEvent,
  CleanStateResponse,
  DashboardSummary,
  DashboardDevice,
  DeviceAuditEventsPage,
  DemoSession,
  PageKey,
  ScenarioResultsPage,
  ServiceHealth,
} from "./types";

const defaultHealth: ServiceHealth = {
  status: "unknown",
  label: "Service",
  detail: "Checking",
};

const initialSession: DemoSession = {
  selectedDeviceId: undefined,
  devices: [],
  eventLog: [],
  demoData: false,
};

const initialScenarioResults: ScenarioResultsPage = {
  items: [],
  page: 1,
  page_size: 10,
  total: 0,
  total_pages: 1,
};

export default function App() {
  const [activePage, setActivePage] = useState<PageKey>("topology");
  const [session, setSession] = useState<DemoSession>(initialSession);
  const [busyAction, setBusyAction] = useState<string>();
  const [cleanStateOpen, setCleanStateOpen] = useState(false);
  const [cleanStateRunning, setCleanStateRunning] = useState(false);
  const [cleanStateResponse, setCleanStateResponse] = useState<CleanStateResponse>();
  const [topologyResetKey, setTopologyResetKey] = useState(0);
  const [lastResult, setLastResult] = useState<ActionResult>();
  const [health, setHealth] = useState({
    issuer: { ...defaultHealth, label: "Issuer" },
    verifier: { ...defaultHealth, label: "Verifier" },
    fabricAdapter: { ...defaultHealth, label: "Fabric Adapter" },
  });
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [walletTimelinePage, setWalletTimelinePage] = useState(1);
  const [selectedScenarioDeviceId, setSelectedScenarioDeviceId] = useState<string>();
  const [runningScenarioId, setRunningScenarioId] = useState<string>();
  const [scenarioResultsPage, setScenarioResultsPage] = useState(1);
  const [scenarioResults, setScenarioResults] = useState<ScenarioResultsPage>(initialScenarioResults);
  const [walletTimeline, setWalletTimeline] = useState<DeviceAuditEventsPage>({
    items: [],
    page: 1,
    page_size: 10,
    total: 0,
    total_pages: 1,
  });

  const selectedDevice = useMemo(
    () => session.devices.find((device) => device.id === session.selectedDeviceId),
    [session.devices, session.selectedDeviceId],
  );
  const selectedDeviceReady = Boolean(selectedDevice?.did && selectedDevice.status === "active");
  const selectedDeviceSelectable = Boolean(selectedDevice?.did);
  const actionPending = Boolean(busyAction) || cleanStateRunning;

  const refreshRuntime = useCallback(async () => {
    const [devices, audit, accumulatorState, summaryResult] = await Promise.all([
      getDashboardDevices(),
      getAuditEvents(1, 50),
      getAccumulatorState().catch(() => null),
      getLedgerSummary()
        .then((summary): SummaryResult => ({ ok: true, summary }))
        .catch((error): SummaryResult => ({ ok: false, detail: errorMessage(error) })),
    ]);
    setHealth(
      summaryResult.ok
        ? serviceHealthFromLedgerSummary(summaryResult.summary)
        : {
            issuer: { status: "error", label: "Issuer", detail: summaryResult.detail },
            verifier: { status: "error", label: "Verifier", detail: summaryResult.detail },
            fabricAdapter: {
              status: "error",
              label: "Fabric Adapter",
              detail: summaryResult.detail,
            },
          },
    );
    setAuditEvents(audit.items);
    setSession((current) => {
      const selectedStillExists = devices.some(
        (device) => device.id === current.selectedDeviceId,
      );
      return {
        ...current,
        devices,
        selectedDeviceId: selectedStillExists
          ? current.selectedDeviceId
          : devices[0]?.id,
        accumulatorState: accumulatorState || current.accumulatorState,
        ledgerSummary: summaryResult.ok ? summaryResult.summary : undefined,
        demoData: false,
      };
    });
  }, []);

  useEffect(() => {
    refreshRuntime().catch((error) =>
      setLastResult({ ok: false, title: "Dashboard API", message: errorMessage(error) }),
    );
    const timer = window.setInterval(() => {
      refreshRuntime().catch(() => undefined);
    }, 8000);
    return () => window.clearInterval(timer);
  }, [refreshRuntime]);

  useEffect(() => {
    setWalletTimelinePage(1);
  }, [session.selectedDeviceId]);

  useEffect(() => {
    setSelectedScenarioDeviceId((current) =>
      current && session.devices.some((device) => device.id === current) ? current : undefined,
    );
  }, [session.devices]);

  const refreshWalletTimeline = useCallback(async () => {
    if (!session.selectedDeviceId) {
      setWalletTimeline({
        items: [],
        page: 1,
        page_size: 10,
        total: 0,
        total_pages: 1,
      });
      return;
    }
    const page = await getDeviceAuditEvents(session.selectedDeviceId, walletTimelinePage, 10);
    setWalletTimeline(page);
  }, [session.selectedDeviceId, walletTimelinePage]);

  useEffect(() => {
    if (activePage !== "wallet") return;
    refreshWalletTimeline().catch((error) =>
      setLastResult({ ok: false, title: "Device Timeline", message: errorMessage(error) }),
    );
  }, [activePage, refreshWalletTimeline]);

  const refreshScenarioResults = useCallback(async (page = scenarioResultsPage) => {
    const resultPage = await getScenarioResults(page, 10);
    setScenarioResults(resultPage);
    setScenarioResultsPage(resultPage.page);
  }, [scenarioResultsPage]);

  useEffect(() => {
    if (activePage !== "security") return;
    refreshScenarioResults().catch((error) =>
      setLastResult({ ok: false, title: "Scenario Results", message: errorMessage(error) }),
    );
  }, [activePage, refreshScenarioResults]);

  const timelineEvents = useMemo(() => {
    if (auditEvents.length) return auditEvents;
    return session.eventLog;
  }, [auditEvents, session.eventLog]);

  const commonActions = {
    addDevice: () => run("add-device", "Device DID", addDevice),
    issueIdentity: () => run("identity", "Identity VC", issueIdentity),
    issueCapability: () => run("capability", "Capability VC", issueCapability),
    authorizeRead: () => run("authorize", "Authorization", authorizeRead),
    revokeCapability: () => run("revoke", "Revocation", revokeCapability),
    restoreAccess: () => run("restore", "Restore Access", restoreAccess),
    refreshProof: () => run("refresh", "Proof Refresh", refreshSelectedProofs),
    wrongAction: () => run("wrong-action", "Wrong Action", wrongAction),
    badSignature: () => run("bad-signature", "Bad Signature", badSignature),
    happyPath: () => run("happy-path", "Happy Path", happyPath),
    revocationScenario: () => run("revocation", "Revocation Scenario", revocationScenario),
    runBenchmark: () =>
      run("benchmark", "Benchmark", async () => {
        setActivePage("performance");
        return "Live benchmark execution requires dashboard backend.";
      }),
  };

  return (
    <>
    <Layout
      activePage={activePage}
      onNavigate={setActivePage}
      health={health}
      controlsDisabled={cleanStateRunning}
      onCleanState={() => {
        setCleanStateResponse(undefined);
        setCleanStateOpen(true);
      }}
    >
      {activePage === "topology" ? (
        <TopologyPage
          key={`topology-${topologyResetKey}`}
          session={session}
          events={timelineEvents}
          busyAction={busyAction}
          actionPending={actionPending}
          selectedDeviceReady={selectedDeviceReady}
          lastResult={lastResult}
          onSelectDevice={selectDevice}
          actions={{
            addDevice: commonActions.addDevice,
            issueIdentity: commonActions.issueIdentity,
            issueCapability: commonActions.issueCapability,
            authorizeRead: commonActions.authorizeRead,
            revokeCapability: commonActions.revokeCapability,
            refreshProof: commonActions.refreshProof,
            runBenchmark: commonActions.runBenchmark,
          }}
        />
      ) : null}
      {activePage === "wallet" ? (
        <DeviceWalletPage
          session={session}
          busyAction={busyAction}
          actionPending={actionPending}
          selectedDeviceReady={selectedDeviceReady}
          selectedDeviceSelectable={selectedDeviceSelectable}
          onSelectDevice={selectDevice}
          timeline={walletTimeline}
          onTimelinePageChange={setWalletTimelinePage}
          actions={{
            addDevice: commonActions.addDevice,
            issueIdentity: commonActions.issueIdentity,
            issueCapability: commonActions.issueCapability,
            refreshProof: commonActions.refreshProof,
            authorizeRead: commonActions.authorizeRead,
            restoreAccess: commonActions.restoreAccess,
            revokeCapability: commonActions.revokeCapability,
          }}
        />
      ) : null}
      {activePage === "ledger" ? <FabricLedgerPage /> : null}
      {activePage === "security" ? (
        <SecurityScenariosPage
          devices={session.devices}
          selectedDeviceId={selectedScenarioDeviceId}
          runningScenarioId={cleanStateRunning ? "clean-state" : runningScenarioId}
          lastResult={lastResult}
          scenarioResults={scenarioResults}
          onSelectDevice={setSelectedScenarioDeviceId}
          onRunScenario={runScenario}
          onResultsPageChange={setScenarioResultsPage}
        />
      ) : null}
      {activePage === "performance" ? <PerformancePage /> : null}
      {activePage !== "topology" &&
      activePage !== "performance" &&
      activePage !== "wallet" &&
      activePage !== "ledger" &&
      activePage !== "security" ? (
        <div className="p-6 pt-0">
          <AuditTimeline events={timelineEvents} demoData={false} />
        </div>
      ) : null}
    </Layout>
    {cleanStateOpen ? (
      <CleanStateModal
        running={cleanStateRunning}
        response={cleanStateResponse}
        onCancel={() => {
          if (!cleanStateRunning) setCleanStateOpen(false);
        }}
        onConfirm={performCleanState}
      />
    ) : null}
    </>
  );

  function selectDevice(deviceId: string) {
    setSession((current) => ({ ...current, selectedDeviceId: deviceId }));
  }

  async function runScenario(scenarioId: string) {
    if (runningScenarioId || busyAction || cleanStateRunning) return;
    if (!selectedScenarioDeviceId) {
      setLastResult({
        ok: false,
        title: "Security Scenario",
        message: "Select a device to run scenarios.",
      });
      return;
    }
    const scenarioTitle = scenarioTitleForId(scenarioId);
    setRunningScenarioId(scenarioId);
    try {
      const response = await runSecurityScenario(scenarioId, selectedScenarioDeviceId);
      setLastResult({
        ok: response.result.status === "pass",
        title: scenarioTitle,
        message: response.result.reason || response.result.status,
      });
      setScenarioResultsPage(1);
      await refreshRuntime();
      await refreshScenarioResults(1);
    } catch (error) {
      setLastResult({ ok: false, title: scenarioTitle, message: errorMessage(error) });
      await refreshRuntime().catch(() => undefined);
      setScenarioResultsPage(1);
      await refreshScenarioResults(1).catch(() => undefined);
    } finally {
      setRunningScenarioId(undefined);
    }
  }

  async function run(
    actionId: string,
    title: string,
    task: () => Promise<string>,
  ) {
    if (busyAction || cleanStateRunning) return;
    setBusyAction(actionId);
    try {
      const message = await task();
      setLastResult({ ok: actionId !== "benchmark", title, message });
      await refreshRuntime();
      if (activePage === "wallet") {
        await refreshWalletTimeline();
      }
    } catch (error) {
      setLastResult({ ok: false, title, message: errorMessage(error) });
    } finally {
      setBusyAction(undefined);
    }
  }

  async function performCleanState(options: {
    confirm: string;
  }) {
    if (cleanStateRunning) return;
    setCleanStateRunning(true);
    setCleanStateResponse(undefined);
    try {
      const response = await cleanDashboardState(options);
      setCleanStateResponse(response);
      if (!response.ok) {
        throw new Error(response.error || response.message || "Clean state failed");
      }
      setSession(initialSession);
      setAuditEvents([]);
      setTopologyResetKey((current) => current + 1);
      setLastResult({
        ok: true,
        title: "Reset Demo Session",
        message: response.message || "Demo session reset. Fabric ledger was not changed.",
      });
      await refreshRuntime();
    } catch (error) {
      setLastResult({
        ok: false,
        title: "Reset Demo Session",
        message: errorMessage(error),
      });
    } finally {
      setCleanStateRunning(false);
    }
  }

  async function addDevice(): Promise<string> {
    const tempId = `pending-${crypto.randomUUID()}`;
    const pendingDevice: DashboardDevice = {
      id: tempId,
      label: `device-${String(session.devices.length + 1).padStart(2, "0")}`,
      status: "pending",
      capabilityStatus: "not-issued",
    };
    setSession((current) => ({
      ...current,
      selectedDeviceId: tempId,
      devices: [...current.devices, pendingDevice],
    }));
    const device = await createDashboardDevice(pendingDevice.label);
    setSession((current) => ({
      ...current,
      selectedDeviceId: device.id,
      devices: current.devices
        .filter((candidate) => candidate.id !== tempId)
        .concat(device),
      eventLog: [event("DID_REGISTERED", device.did || device.id), ...current.eventLog],
    }));
    return `Created ${device.did}`;
  }

  async function issueIdentity(): Promise<string> {
    const device = requireSelectedDevice();
    const updated = await issueIdentityForDevice(device.id);
    applyDeviceUpdate(updated, "IDENTITY_VC_ISSUED", updated.identityVc?.id || updated.did || updated.id);
    return `Issued identity credential ${updated.identityVc?.id || ""}`;
  }

  async function issueCapability(): Promise<string> {
    const device = requireSelectedDevice();
    const updated = await issueCapabilityForDevice(device.id);
    const accumulatorState = await getAccumulatorState().catch(() => null);
    applyDeviceUpdate(
      updated,
      "CAPABILITY_VC_ISSUED",
      updated.capabilityVc?.id || updated.did || updated.id,
      accumulatorState,
    );
    return `Issued capability credential ${updated.capabilityVc?.id || ""}`;
  }

  async function refreshSelectedProofs(): Promise<string> {
    const device = requireSelectedDevice();
    const updated = await refreshProofForDevice(device.id);
    applyDeviceUpdate(
      updated,
      "PROOF_REFRESHED",
      updated.capabilityVc?.id || updated.identityVc?.id || updated.did || updated.id,
      await getAccumulatorState().catch(() => null),
    );
    return "Refreshed selected device accumulator proofs.";
  }

  async function authorizeRead(): Promise<string> {
    const device = requireSelectedDevice();
    const response = await authorizeDevice({ deviceId: device.id });
    applyDeviceUpdate(
      response.device,
      response.decision.decision === "allow" ? "AUTH_ALLOW" : "AUTH_DENY",
      response.decision.reason || response.decision.decision,
    );
    return `${response.decision.decision}${response.decision.reason ? `: ${response.decision.reason}` : ""}`;
  }

  async function wrongAction(): Promise<string> {
    const device = requireSelectedDevice();
    const response = await authorizeDevice({ deviceId: device.id, action: "write" });
    applyDeviceUpdate(response.device, "AUTH_DENY", response.decision.reason || "wrong action");
    return `${response.decision.decision}: ${response.decision.reason}`;
  }

  async function badSignature(): Promise<string> {
    const device = requireSelectedDevice();
    const response = await authorizeDevice({
      deviceId: device.id,
      tamperSignature: true,
    });
    applyDeviceUpdate(response.device, "AUTH_DENY", response.decision.reason || "bad signature");
    return `${response.decision.decision}: ${response.decision.reason}`;
  }

  async function revokeCapability(): Promise<string> {
    const device = requireSelectedDevice();
    const updated = await revokeDeviceCapability(device.id);
    applyDeviceUpdate(
      updated,
      "VC_REVOKED",
      updated.capabilityVc?.id || updated.did || updated.id,
      await getAccumulatorState().catch(() => null),
    );
    return `Revoked ${updated.capabilityVc?.id || "capability credential"}`;
  }

  async function restoreAccess(): Promise<string> {
    const device = requireSelectedDevice({ allowRevoked: true });
    if (device.status !== "revoked") {
      throw new Error("Restore Access is only available for revoked devices.");
    }

    const restored = await restoreDeviceAccess(device.id);
    applyDeviceUpdate(
      restored,
      "ACCESS_RESTORED",
      restored.capabilityVc?.id || restored.did || restored.id,
      await getAccumulatorState().catch(() => null),
    );
    return "Access restored with fresh credentials.";
  }

  async function happyPath(): Promise<string> {
    let device = selectedDevice;
    if (!device) {
      device = await createDashboardDevice(`device-${String(session.devices.length + 1).padStart(2, "0")}`);
      applyDeviceUpdate(device, "DID_REGISTERED", device.did || device.id);
    }
    if (!device.identityVc) {
      device = await issueIdentityForDevice(device.id);
      applyDeviceUpdate(device, "IDENTITY_VC_ISSUED", device.identityVc?.id || device.did || device.id);
    }
    if (!device.capabilityVc) {
      device = await issueCapabilityForDevice(device.id);
      applyDeviceUpdate(device, "CAPABILITY_VC_ISSUED", device.capabilityVc?.id || device.did || device.id);
    }
    const response = await authorizeDevice({ deviceId: device.id });
    applyDeviceUpdate(
      response.device,
      response.decision.decision === "allow" ? "AUTH_ALLOW" : "AUTH_DENY",
      response.decision.reason || response.decision.decision,
    );
    return `Completed happy path with ${response.decision.decision}.`;
  }

  async function revocationScenario(): Promise<string> {
    let device = requireSelectedDevice();
    if (!device.capabilityVc) {
      device = await issueCapabilityForDevice(device.id);
      applyDeviceUpdate(device, "CAPABILITY_VC_ISSUED", device.capabilityVc?.id || device.did || device.id);
    }
    const updated = await revokeDeviceCapability(device.id, "device revocation scenario");
    applyDeviceUpdate(updated, "VC_REVOKED", updated.capabilityVc?.id || updated.did || updated.id);
    return "Selected device capability credential revoked.";
  }

  function requireSelectedDevice(options?: { allowRevoked?: boolean }): DashboardDevice {
    const device = session.devices.find((item) => item.id === session.selectedDeviceId);
    if (!device) throw new Error("Select a device first.");
    if (!device.did) {
      throw new Error("Selected device is not ready yet.");
    }
    if (!options?.allowRevoked && device.status !== "active") {
      throw new Error("Selected device is not active.");
    }
    return device;
  }

  function applyDeviceUpdate(
    updated: DashboardDevice,
    eventType: string,
    subjectOrCredential: string,
    accumulatorState?: AccumulatorState | null,
  ) {
    setSession((current) => ({
      ...current,
      selectedDeviceId: updated.id,
      devices: upsertDevice(current.devices, updated),
      accumulatorState: accumulatorState || current.accumulatorState,
      eventLog: [event(eventType, subjectOrCredential), ...current.eventLog].slice(0, 30),
    }));
  }
}

type SummaryResult =
  | { ok: true; summary: DashboardSummary }
  | { ok: false; detail: string };

function upsertDevice(devices: DashboardDevice[], updated: DashboardDevice): DashboardDevice[] {
  const exists = devices.some((device) => device.id === updated.id);
  if (!exists) return [...devices, updated];
  return devices.map((device) => (device.id === updated.id ? updated : device));
}

function event(eventType: string, subjectOrCredential: string): AuditEvent {
  return {
    event_id: crypto.randomUUID(),
    event_type: eventType,
    service: "dashboard",
    subject_did: subjectOrCredential.startsWith("did:") ? subjectOrCredential : undefined,
    credential_id: subjectOrCredential.startsWith("did:") ? undefined : subjectOrCredential,
    created_at: new Date().toISOString(),
  };
}

function scenarioTitleForId(scenarioId: string): string {
  const titles: Record<string, string> = {
    "happy-path": "Happy Path",
    "wrong-action": "Wrong Action Attack",
    "bad-signature": "Bad Signature Attack",
    revocation: "Revocation Scenario",
    "proof-refresh": "Proof Refresh Scenario",
  };
  return titles[scenarioId] || "Security Scenario";
}

function CleanStateModal({
  running,
  response,
  onCancel,
  onConfirm,
}: {
  running: boolean;
  response?: CleanStateResponse;
  onCancel: () => void;
  onConfirm: (options: {
    confirm: string;
  }) => void;
}) {
  const [confirm, setConfirm] = useState("");
  const canSubmit = confirm === "RESET" && !running;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-2xl rounded border border-line/40 bg-panel p-5 shadow-2xl">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-danger">Reset Demo Session</h2>
          <p className="mt-2 text-sm leading-6 text-muted">
            This clears registered devices, stored VCs, proofs, local device events, selected device state, and UI session data. It does not reset Hyperledger Fabric ledger data.
          </p>
        </div>

        <label className="block text-sm text-text">
          Type RESET to confirm
          <input
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            disabled={running}
            className="mt-2 w-full rounded border border-line/50 bg-background px-3 py-2 font-mono text-sm text-text outline-none focus:border-danger/70 disabled:opacity-60"
          />
        </label>

        <div className="mt-4 rounded border border-line/35 bg-background/70 p-3 text-sm text-muted">
          <div className="font-mono text-[11px] uppercase text-text">Full ledger reset</div>
          <p className="mt-2">
            For a full ledger reset, run manually from Git Bash:
          </p>
          <pre className="mt-2 whitespace-pre-wrap font-mono text-[11px] leading-5 text-cyan">{`cd fabric
bash ./network.sh down
bash ./network.sh up
bash ./network.sh deployCC-docker
bash ./network.sh ping`}</pre>
        </div>

        {running ? (
          <div className="mt-4 rounded border border-orange/35 bg-orange/10 px-3 py-2 font-mono text-xs uppercase text-orange">
            Clean state running...
          </div>
        ) : null}

        {response?.message || response?.error ? (
          <div
            className={`mt-4 rounded border px-3 py-2 text-sm ${
              response.ok
                ? "border-green/35 bg-green/10 text-green"
                : "border-danger/35 bg-danger/10 text-danger"
            }`}
          >
            {response.error || response.message}
          </div>
        ) : null}

        <div className="mt-5 flex justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            disabled={running}
            className="rounded border border-line/50 px-4 py-2 text-sm text-muted transition hover:text-text disabled:cursor-wait disabled:opacity-60"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onConfirm({ confirm })}
            disabled={!canSubmit}
            className="rounded border border-danger/60 bg-danger/15 px-4 py-2 text-sm font-semibold text-danger transition hover:bg-danger/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Reset Demo Session
          </button>
        </div>
      </div>
    </div>
  );
}
