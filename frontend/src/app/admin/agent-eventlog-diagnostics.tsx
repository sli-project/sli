import { EMPTY_VALUE } from "../../shared/format";
import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";

export function AgentEventlogDiagnostics({ agent, timeZone = "UTC" }: { agent: AgentItem; timeZone?: string }) {
  const report = agent.eventlog_diagnostics;
  const budget = Math.max(120, (agent.collection_policy?.interval_seconds ?? 60) * 6 + 120) * 1000;
  return <details><summary>{t("agents.eventlog.title")}</summary>
    {!report?.items.length ? <p>{t("agents.eventlog.awaiting")}</p> : <>
      <p>{t("agents.eventlog.received", { date: formatDateTime(report.reported_at, timeZone) })}</p>
      <ul>{report.items.map((item) => <li key={item.channel}>
        <strong>{item.channel}</strong> · {t(item.error ? "agents.eventlog.failed" : "agents.eventlog.ok")}
        <p>{formatDateTime(item.observed_at_utc, timeZone)} · {t("agents.auditRevision", { revision: item.policy_revision })}</p>
        {item.policy_revision !== agent.applied_policy_revision || Date.now() - Date.parse(item.observed_at_utc) > budget
          ? <p role="status">{t("agents.eventlog.stale")}</p> : null}
        {item.error ? <p>{item.error.exception_class} · Win32: {item.error.winerror ?? EMPTY_VALUE} · HRESULT: {item.error.hresult === null ? EMPTY_VALUE : `0x${(item.error.hresult >>> 0).toString(16).padStart(8, "0")}`} · {t("agents.eventlog.position", {
          record: item.error.record_id ?? EMPTY_VALUE, bookmark: t(item.error.bookmark_present ? "agents.on" : "agents.off"), stage: item.error.stage,
        })}</p> : null}
      </li>)}</ul>
    </>}
  </details>;
}
