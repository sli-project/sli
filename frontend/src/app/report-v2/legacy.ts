import { dayKey } from "../../shared/date-time";
/**
 * Old «Действия безопасности» deep links (`/app/security-events-report?...`)
 * are still stored in investigations as `return_to`. They are translated to
 * the v2 report URL so "back" keeps its filters.
 */

const DIRECT = ["category", "outcome", "event_id", "actor", "target", "group", "source", "q", "entity_id", "event_db_id"] as const;

function calendarDate(value: string, timeZone: string): string | null {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : null;
  try {
    return dayKey(date, timeZone);
  } catch {
    return date.toISOString().slice(0, 10);
  }
}

export function legacySecurityEventsHref(search: string): string {
  const old = new URLSearchParams(search);
  const next = new URLSearchParams();
  const domain = old.get("domain_id");
  if (domain) next.set("domain", domain);
  const timeZone = old.get("timezone") || "UTC";
  const from = old.get("time_from");
  const to = old.get("time_to");
  if (from && to && from.includes("T") && to.includes("T")) {
    // Exact evidence window: passed through unchanged (the end stays exclusive), never widened to days.
    next.set("period", "custom");
    next.set("from", from);
    next.set("to", to);
    next.set("tz", timeZone);
  } else if (from && to) {
    const first = calendarDate(from, timeZone);
    const last = calendarDate(to, timeZone);
    if (first && last && first <= last) {
      next.set("period", "custom");
      next.set("from", first);
      next.set("to", last);
    }
  }
  for (const key of DIRECT) {
    const value = old.get(key);
    if (value) next.set(key, value);
  }
  if (old.get("tab") === "chains") next.set("tab", "chains");
  const query = next.toString();
  return `/app/report/security.events.chains${query ? `?${query}` : ""}`;
}

export { legacyLogonsHref } from "../../plugins/ad/legacy";

/** Internal links carry the current report view back as `return_to`. */
export function withReturnTo(href: string, current: string): string {
  if (!href.startsWith("/app/")) return href;
  const hashAt = href.indexOf("#");
  const hash = hashAt >= 0 ? href.slice(hashAt) : "";
  const withoutHash = hashAt >= 0 ? href.slice(0, hashAt) : href;
  const queryAt = withoutHash.indexOf("?");
  const path = queryAt >= 0 ? withoutHash.slice(0, queryAt) : withoutHash;
  const params = new URLSearchParams(queryAt >= 0 ? withoutHash.slice(queryAt + 1) : "");
  params.set("return_to", current);
  return `${path}?${params.toString()}${hash}`;
}
