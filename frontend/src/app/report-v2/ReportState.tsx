import { useTimeZone } from "../../shared/time-zone";
import type { ReactNode } from "react";
import type { ReportStateDetails } from "../../api/report-v2-types";
import { formatDateTime, StateView, type ResultState } from "../../design-system";
import { t } from "../../i18n";
import { resolveMessage, type ApiMessage } from "../../i18n/messages";
import { knownTime } from "./FreshnessTimes";

function sourceId(details?: ReportStateDetails): string | undefined {
  const source = details?.source;
  if (typeof source === "string") return source.trim() || undefined;
  if (!source) return undefined;
  for (const key of ["hostname", "name", "source_name"]) {
    const value = source[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function sourceIssues(details?: ReportStateDetails): NonNullable<ReportStateDetails["source_issues"]> {
  const source = sourceId(details);
  const missing = details?.missing_sources?.length ? details.missing_sources : source ? [source] : [];
  return details?.source_issues?.length ? details.source_issues.filter((issue) => issue.source.trim())
    : missing.filter((source) => source.trim()).map((source) => ({ source, reason: details!.reason,
      since_utc: details?.reason === "freshness_exceeded" ? details.stale_since_utc : null }));
}

/**
 * Persisted report state (docs/UI_STANDARD.md, rules 2 and 3).
 * A lagging or silent source is one plain line with its name and time; only a failed request is a block.
 */
export function ReportState({ state: requestedState, message, details, detail, subject, actions, onRetry, compact = false }: {
  state: ResultState;
  message?: ApiMessage;
  details?: ReportStateDetails;
  detail?: ReactNode;
  subject?: string;
  actions?: ReactNode;
  onRetry?: () => void;
  compact?: boolean;
  canDiagnose?: boolean;
}) {
  const { timeZone } = useTimeZone();
  // Old servers may still return unavailable. It is never a successful zero.
  const state = requestedState === "unavailable" ? "error" : requestedState;
  if (state === "ok") return null;
  if (state === "loading") return <StateView state="loading"/>;
  if (state === "error") {
    const specific = message?.code && !message.code.startsWith("reports.states.error.") ? resolveMessage(message, "") : "";
    return <div className="sli-ds-state" data-state="error" role="alert">
      <div>{specific || detail || (subject ? t("reports.states.load_failed", { subject }) : t("reports.states.error.title"))}</div>
      {actions}
      {onRetry ? <button type="button" className="sli-ds-button" onClick={onRetry}>{t("state.retry")}</button> : null}
    </div>;
  }
  if (state === "empty" || state === "denied") return <StateView state={state} titleMessage={message} compact={compact} onRetry={onRetry}
    actions={actions} message={t(`reports.states.${state}.text`)} detail={detail}/>;
  const silent = sourceIssues(details).find((issue) => knownTime(issue.since_utc));
  return silent ? <p className="sli-ds-muted" role="status">{t("reports.states.silent_source", {
    source: silent.source_name?.trim() || silent.source, time: formatDateTime(silent.since_utc, true, timeZone),
  })}</p> : null;
}
