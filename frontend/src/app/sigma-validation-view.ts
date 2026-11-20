import type { SigmaHistoryExecution, SigmaValidationResponse, SigmaValidationRule } from "../api/sigma-types";
import { t, type MessageKey } from "../i18n";

export type SigmaValidationRow = {
  key: string;
  rule: SigmaValidationRule;
  execution?: SigmaHistoryExecution;
  state: string;
};

/** Каждая версия исполнения остаётся отдельной строкой, без суммирования повторных проверок. */
export function sigmaValidationRows(data: SigmaValidationResponse): SigmaValidationRow[] {
  if (data.state !== "available") return [];
  return data.rules.flatMap((rule) => rule.executions.length
    ? rule.executions.map((execution) => ({ rule, execution, state: execution.state,
      key: JSON.stringify([rule.rule_id, rule.raw_sha256, execution.manifest_sha256, execution.plan_sha256,
        execution.compiler_version, execution.mapping_version, execution.overlay_sha256]) }))
    : [{ rule, state: rule.compile_state === "unsupported" ? "blocked" : "not_checked",
      key: JSON.stringify([rule.rule_id, rule.raw_sha256]) }]);
}

const labels: Record<string, MessageKey> = {
  blocked: "security.sigma.state.blocked", not_checked: "security.sigma.state.not_checked",
  no_data: "security.sigma.state.no_data", no_matches: "security.sigma.state.no_matches",
  matched: "security.sigma.state.matched", degraded: "security.sigma.state.degraded",
  not_evaluable: "security.sigma.state.not_evaluable", incomplete: "security.sigma.state.incomplete",
  completed: "security.sigma.status.completed", partial: "security.sigma.status.partial",
  cancelled: "security.sigma.status.cancelled", failed: "security.sigma.status.failed",
};
export function sigmaStateLabel(state: string): string {
  return t(Object.hasOwn(labels, state) ? labels[state] : "security.sigma.state.unknown");
}

const reasons: Record<string, MessageKey> = {
  source_unavailable_or_denied: "security.sigma.reason.source",
  catalog_unavailable: "security.sigma.reason.catalog",
  projection_limit: "security.sigma.reason.limit",
  projection_unavailable: "security.sigma.reason.unavailable",
  payload_unavailable: "security.sigma.reason.payload",
  field_unavailable: "security.sigma.reason.field_unavailable",
  field_missing: "security.sigma.reason.field_missing",
  field_null: "security.sigma.reason.field_null",
  field_size_limit: "security.sigma.reason.field_size_limit",
  mapping_version_mismatch: "security.sigma.reason.mapping",
  mapping_schema_unsupported: "security.sigma.reason.mapping",
  mapping_invalid: "security.sigma.reason.mapping",
  mapping_unavailable: "security.sigma.reason.mapping",
  time_limit: "security.sigma.reason.budget", work_limit: "security.sigma.reason.budget",
  regex_timeout: "security.sigma.reason.budget",
};
export function sigmaReasonLabel(reason: string): string {
  return t(Object.hasOwn(reasons, reason) ? reasons[reason] : "security.sigma.reason.unknown");
}
