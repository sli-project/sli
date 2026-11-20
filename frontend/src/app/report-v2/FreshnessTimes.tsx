import { useTimeZone } from "../../shared/time-zone";
import { formatDateTime } from "../../design-system";
import { t } from "../../i18n";
import { formatRelative, formatDateTime as formatInZone } from "../../shared/date-time";

type Freshness = { event?: unknown; snapshot?: unknown; published?: unknown; observed?: unknown; timeZone?: string };

export function knownTime(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
}

/** Prefer source data; a recent publication cannot refresh an old observation. */
export function freshnessSummary({ event, snapshot, published, observed, timeZone }: Freshness): string | null {
  const sourceTime = [observed, snapshot, event].find(knownTime);
  const value = sourceTime ?? (knownTime(published) ? published : null);
  if (!value) return null;
  const time = timeZone ? formatInZone(value, timeZone, { withTime: false }) : formatDateTime(value, false);
  const age = formatRelative(value, { daysOnly: true });
  return t(sourceTime ? "reports.freshness.data_date" : "reports.freshness.publication_date", { time, age });
}

/** Only known clocks are shown, separately, inside the caller's disclosure. */
export function FreshnessTimes({ event, snapshot, published, observed, timeZone }: Freshness) {
  const selected = useTimeZone();
  timeZone ??= selected.timeZone;
  const clocks = [
    ["reports.freshness.event", event], ["reports.freshness.snapshot", snapshot],
    ["reports.freshness.published", published], ["reports.passport.observed", observed],
  ] as const;
  return <>{clocks.map(([key, value]) => {
    if (!knownTime(value)) return null;
    const time = timeZone ? formatInZone(value, timeZone) : formatDateTime(value);
    return <div key={key}><span>{t(key, { time, value: time })}</span></div>;
  })}</>;
}
