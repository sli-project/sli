import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { agentModuleName } from "./agent-actions";
import { deliveryReason, deliveryView } from "./agent-delivery-diagnostics-model";

export function AgentDeliveryDiagnostics({ agent, timeZone = "UTC", recoveryAvailable = false }: {
  agent: AgentItem; timeZone?: string; recoveryAvailable?: boolean;
}) {
  const view = deliveryView(agent.delivery_diagnostics, agent.collection_policy?.interval_seconds);
  const date = (value: string | null) => formatDateTime(value, timeZone);
  if (agent.delivery_diagnostics == null) return null;
  return <details><summary>{t("agents.delivery.title")}</summary>
    {view.state !== "records" ? <p>{t(view.state === "empty" ? "agents.delivery.empty" : "agents.delivery.unknown")}</p> : null}
    {view.reportedAt ? <p>{t("agents.delivery.received", { date: date(view.reportedAt) })}</p> : null}
    {view.state !== "unknown" && view.stale ? <p role="status">{t("agents.delivery.stale")}</p> : null}
    {view.partial ? <p role="status">{t("agents.delivery.partial")}</p> : null}
    <ul>{view.items.map((item) => <li key={item.module_id}>
      <strong>{agentModuleName(item.module_id)}</strong> · {t(item.resolved_at_utc ? "agents.delivery.resolved" : "agents.delivery.failed")}
      <p>{t(deliveryReason(item.error_code))}</p>
      <p>{t("agents.delivery.observed", { date: date(item.observed_at_utc) })}</p>
      {item.resolved_at_utc ? <p>{t("agents.delivery.resolvedAt", { date: date(item.resolved_at_utc) })}</p> : <p>{t(item.error_code === "agent_sequence_gap" || item.error_code === "agent_cursor_mismatch" ? "agents.delivery.action.gap" : "agents.delivery.action.inspect")}</p>}
      {!item.resolved_at_utc && recoveryAvailable && (item.error_code === "agent_sequence_gap" || item.error_code === "agent_cursor_mismatch")
        ? <a href={`#agent-sequence-recovery-${agent.id}`}>{t("agents.delivery.recovery")}</a> : null}
      <details><summary>{t("agents.delivery.details")}</summary>
        <p>{t("agents.delivery.packet", { packet: item.packet_id, sequence: item.sequence })}</p>
        <p>{t("agents.delivery.receipt", { status: t(item.receipt_status === "retry_later" ? "agents.delivery.receipt.retry" : item.receipt_status === "rejected" ? "agents.delivery.receipt.rejected" : item.receipt_status === "invalid" ? "agents.delivery.receipt.invalid" : "agents.delivery.receipt.unavailable"), http: item.http_status ?? t("agents.noData") })}</p>
      </details>
    </li>)}</ul>
  </details>;
}

