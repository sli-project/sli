import { dayKey } from "../../shared/date-time";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import type { ReportResultDto } from "../../api/report-v2-types";
import { formatDateTime, type PeriodValue } from "../../design-system";
import { t } from "../../i18n";

type EmptyRecovery = { lastAt: string | null; period: PeriodValue | null; sourceHref: string; originalPeriod: string | null };

function validInstant(value: unknown): string | null {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value)) ? value : null;
}

/** Availability metadata is optional. Never substitute generation time or the requested window. */
export function reportEmptyRecovery(result: ReportResultDto | undefined, timeZone: string, requestedPeriod?: PeriodValue): EmptyRecovery | null {
  if (!result) return null;
  const coverage = result.coverage;
  const lastAt = validInstant(coverage.history_to_utc) ?? validInstant(coverage.observed_at_utc);
  const source = coverage.source;
  const hostname = typeof source === "object" && source !== null && "hostname" in source && typeof source.hostname === "string" ? source.hostname.trim() : null;
  if (!lastAt && !hostname && !coverage.state) return null;
  let period: PeriodValue | null = null;
  if (lastAt) {
    try {
      const day = dayKey(lastAt, timeZone) as string;
      period = { preset: "custom", from: day, to: day };
    } catch { /* An unavailable timezone cannot yield a truthful calendar window. */ }
  }
  const from = validInstant(result.window.from_utc);
  const to = validInstant(result.window.to_utc_exclusive) ?? validInstant(result.window.to_utc);
  let originalPeriod = from && to ? t("reports.empty.original_period", { from: formatDateTime(from, true, timeZone), to: formatDateTime(to, true, timeZone) }) : null;
  if (!originalPeriod && requestedPeriod) {
    if (requestedPeriod.preset === "custom" && requestedPeriod.from && requestedPeriod.to) originalPeriod = t("reports.empty.original_period", { from: requestedPeriod.from, to: requestedPeriod.to });
    else if (requestedPeriod.preset !== "custom") originalPeriod = t("reports.empty.original_selection", { period: t(`period.${requestedPeriod.preset}`) });
  }
  return { lastAt, period, sourceHref: hostname ? `/app/operations/sources/${encodeURIComponent(hostname)}` : "/app/operations",
    originalPeriod };
}

export function EmptyRecoveryDetail({ recovery }: { recovery: EmptyRecovery | null }) {
  const { formatDateTime } = useDateFormatters();
  return recovery ? <>
    {recovery.lastAt ? <p>{t("reports.empty.latest_at", { time: formatDateTime(recovery.lastAt) })}</p> : null}
    {recovery.originalPeriod ? <p>{recovery.originalPeriod}</p> : null}
  </> : null;
}

export function EmptyRecoveryActions({ recovery, onShowLatest }: { recovery: EmptyRecovery | null; onShowLatest?: () => void }) {
  return recovery ? <>
    {onShowLatest && recovery.period ? <button type="button" className="sli-ds-button" data-variant="primary" onClick={onShowLatest}>{t("reports.empty.show_latest")}</button> : null}
    <a href={recovery.sourceHref}>{t("reports.empty.source_diagnostics")}</a>
  </> : null;
}
