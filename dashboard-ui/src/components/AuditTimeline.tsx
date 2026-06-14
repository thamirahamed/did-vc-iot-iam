import { ListChecks } from "lucide-react";
import type { AuditEvent } from "../types";

type AuditTimelineProps = {
  events: AuditEvent[];
  demoData?: boolean;
};

export default function AuditTimeline({ events, demoData }: AuditTimelineProps) {
  const rows = events.slice(0, 8);
  return (
    <section className="glass-card flex h-full min-h-[270px] flex-col overflow-hidden rounded">
      <div className="flex items-center justify-between border-b border-line/30 p-4">
        <h3 className="flex items-center gap-2 font-mono text-xs uppercase tracking-wide text-muted">
          <ListChecks size={16} /> Event Timeline
        </h3>
        {demoData ? (
          <span className="rounded border border-orange/40 bg-orange/10 px-2 py-1 font-mono text-[10px] uppercase text-orange">
            demo data
          </span>
        ) : null}
      </div>
      <div className="overflow-auto">
        <table className="w-full min-w-[680px] text-left text-sm">
          <thead className="sticky top-0 bg-panel">
            <tr className="border-b border-line/30 font-mono text-[10px] uppercase text-muted">
              <th className="px-4 py-3">Event</th>
              <th className="px-4 py-3">Service</th>
              <th className="px-4 py-3">Device</th>
              <th className="px-4 py-3">Subject / Credential</th>
              <th className="px-4 py-3">Result</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((event, index) => (
              <tr
                key={`${event.event_id || event.event_type || "event"}-${index}`}
                className="border-b border-line/20 last:border-b-0"
              >
                <td className="px-4 py-3 font-mono text-xs text-cyan">
                  {event.event_type || "EVENT"}
                </td>
                <td className="px-4 py-3 text-muted">{event.service || "dashboard"}</td>
                <td className="px-4 py-3 text-muted">
                  {event.device_label || "unknown"}
                </td>
                <td className="max-w-[260px] truncate px-4 py-3 font-mono text-xs">
                  {event.subject_did || event.credential_id || "session"}
                </td>
                <td className="px-4 py-3">
                  <span className={event.decision === "deny" ? "text-danger" : "text-green"}>
                    {event.decision || event.reason || "recorded"}
                  </span>
                </td>
              </tr>
            ))}
            {!rows.length ? (
              <tr>
                <td className="px-4 py-6 text-muted" colSpan={5}>
                  No audit events available yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
