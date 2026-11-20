import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";

type CollectionReadback = Pick<AgentItem, "eventlog_diagnostics" | "policy_revision" | "applied_policy_revision"> & {
  windows_audit?: AgentItem["windows_audit"] | null;
};

const accessDenied = 5;
const logFileFull = 1502;

export function missingAuditSetting(row: { success: boolean; failure: boolean; actual_success: boolean | null; actual_failure: boolean | null }) {
  return row.success && row.actual_success === false || row.failure && row.actual_failure === false;
}

export function collectionDiagnosis(agent: CollectionReadback, timeZone: string, intervalSeconds = 60) {
  const date = (value: string) => formatDateTime(value, timeZone, { withYear: false });
  const freshness = (intervalSeconds * 6 + 120) * 1000;
  const error = agent.eventlog_diagnostics?.items
    .filter((item) => {
      const age = Date.now() - Date.parse(item.observed_at_utc);
      return item.error && item.policy_revision === agent.applied_policy_revision
        && item.policy_revision === agent.policy_revision && age >= 0 && age <= freshness;
    })
    .sort((a, b) => Number(b.channel === "Security") - Number(a.channel === "Security")
      || Date.parse(b.observed_at_utc) - Date.parse(a.observed_at_utc))[0];
  if (error?.error) {
    const hresult = (error.error.hresult ?? 0) >>> 0;
    const code = error.error.winerror ?? (hresult >>> 16 === 0x8007 ? hresult & 0xffff : null);
    const value = { channel: error.channel.slice(0, 200), time: date(error.observed_at_utc) };
    if (code === logFileFull) return { state: t("collectionDiagnosis.logFull", value), action: t("collectionDiagnosis.logFullAction") };
    if (code === accessDenied) return { state: t("collectionDiagnosis.logDenied", value), action: t("systemStatus.action.permissions") };
    return { state: t("collectionDiagnosis.logFailed", value), action: t("systemStatus.action.agent") };
  }
  const audit = agent.windows_audit;
  if (audit?.policy_revision !== agent.policy_revision) return null;
  const missing = audit.families.domain_controller?.required.filter((row) =>
    row.subcategory !== "domain_root_sacl" && missingAuditSetting(row)) ?? [];
  if (!missing.length) return null;
  const domainPolicy = missing.some((row) => row.state === "managed_by_gpo");
  return { state: t(domainPolicy ? "collectionDiagnosis.auditPolicy" : "collectionDiagnosis.auditOff",
    { time: date(audit.checked_at ?? audit.reported_at) }),
  action: t(domainPolicy ? "collectionDiagnosis.auditPolicyAction" : "collectionDiagnosis.auditAction") };
}
