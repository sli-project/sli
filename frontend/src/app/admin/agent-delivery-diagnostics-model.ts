import type { AgentDeliveryDiagnostic } from "../../api/client";

export function deliveryReason(code: string) {
  if (code === "agent_sequence_gap" || code === "agent_cursor_mismatch") return "agents.delivery.reason.gap";
  if (code === "agent_sequence_replayed") return "agents.delivery.reason.replay";
  if (code === "agent_history_pending") return "agents.delivery.reason.historyPending";
  if (code === "agent_transport_failed") return "agents.delivery.reason.transport";
  if (code === "agent_receipt_invalid") return "agents.delivery.reason.receipt";
  if (code === "agent_source_not_bound" || code === "agent_module_not_assigned" || code === "agent_module_unsupported") return "agents.delivery.reason.policy";
  if (code === "agent_replay_window") return "agents.delivery.reason.expired";
  if (code === "agent_workstations_rate_limit" || /^agent_(inbox|snapshot)_(agent_count|agent_bytes|module_count|module_bytes|global_count|global_bytes|storage_bytes)_limit$/.test(code)) return "agents.delivery.reason.capacity";
  if (code === "agent_delivery_rejected") return "agents.delivery.reason.rejected";
  return "agents.delivery.reason.unknown";
}

function diagnostic(value: unknown): value is AgentDeliveryDiagnostic {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  if (typeof item.module_id !== "string" || !/^[a-zA-Z0-9_.-]{1,128}$/.test(item.module_id)
    || typeof item.packet_id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(item.packet_id)
    || typeof item.sequence !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(item.sequence) || BigInt(item.sequence) > 9223372036854775807n
    || typeof item.error_code !== "string" || item.error_code.length > 128
    || typeof item.receipt_status !== "string" || item.receipt_status.length > 32
    || item.http_status !== null && (typeof item.http_status !== "number" || !Number.isInteger(item.http_status) || item.http_status < 100 || item.http_status > 599)
    || typeof item.observed_at_utc !== "string" || !Number.isFinite(Date.parse(item.observed_at_utc))) return false;
  return item.resolved_at_utc === null || typeof item.resolved_at_utc === "string" && Number.isFinite(Date.parse(item.resolved_at_utc))
    && Date.parse(item.resolved_at_utc) >= Date.parse(item.observed_at_utc);
}

export function deliveryView(report: unknown, interval = 60, now = Date.now()) {
  const empty = { state: "unknown" as "unknown" | "empty" | "records", items: [] as AgentDeliveryDiagnostic[], reportedAt: null as string | null, stale: true, partial: false };
  if (!report || typeof report !== "object") return empty;
  const data = report as { reported_at?: unknown; items?: unknown };
  if (!Array.isArray(data.items)) return { ...empty, partial: true };
  const reportedAt = typeof data.reported_at === "string" && Number.isFinite(Date.parse(data.reported_at)) ? data.reported_at : null;
  const budget = Math.max(120, (Number.isFinite(interval) && interval > 0 ? interval : 60) * 6 + 120) * 1000;
  const age = reportedAt ? now - Date.parse(reportedAt) : Infinity;
  const stale = !reportedAt || age > budget || age < -60_000;
  const seen = new Set<string>();
  const items = data.items.slice(0, 16).filter((item): item is AgentDeliveryDiagnostic => {
    if (!diagnostic(item) || seen.has(item.module_id)) return false;
    seen.add(item.module_id); return true;
  });
  const partial = items.length !== data.items.length;
  return { state: items.length ? "records" as const : partial ? "unknown" as const : "empty" as const, items, reportedAt, stale, partial };
}
