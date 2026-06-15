import type {
  AuditEvent,
  DemoSession,
} from "../types";
import AuditTimeline from "./AuditTimeline";
import LiveMetrics from "./LiveMetrics";
import TopologyCanvas from "./topology/TopologyCanvas";

type TopologyPageProps = {
  session: DemoSession;
  events: AuditEvent[];
  onSelectDevice: (deviceId: string) => void;
};

export default function TopologyPage({
  session,
  events,
  onSelectDevice,
}: TopologyPageProps) {
  return (
    <div className="w-full">
      <TopologyCanvas
        devices={session.devices}
        selectedDeviceId={session.selectedDeviceId}
        onSelectDevice={onSelectDevice}
      />
      <div className="grid gap-4 p-6 xl:grid-cols-[0.85fr_2.15fr]">
        <LiveMetrics session={session} />
        <AuditTimeline events={events} demoData={session.demoData} />
      </div>
    </div>
  );
}
