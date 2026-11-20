import { dayKey, formatDateTime } from "../shared/date-time";
import { plural, t } from "../i18n";
import { useState } from "react";
import { VpnDayDrawer } from "./vpn-day-drawer";

type Row = Record<string, unknown>;
type Session = { session_row_id?: string; started_at_utc?: string | null; stopped_at_utc?: string | null; lifecycle_state?: string | null; overlap_violation?: boolean | null };
export type ActivityWindow = { local_from_date?: string | null; local_to_date?: string | null; timezone?: string | null; source_domain_id?: number | null };
export type ActivityDay = { date: string; sessions: Session[]; tone: "confirmed" | "pending" | "violation" | "unknown" | "empty" };

const MAX_DAYS = 3_662;

function localDate(value: string, timeZone: string): string | null {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  try {
    return dayKey(date, timeZone);
  } catch {
    return date.toISOString().slice(0, 10);
  }
}

function nextDay(date: string): string {
  const next = new Date(`${date}T00:00:00Z`);
  next.setUTCDate(next.getUTCDate() + 1);
  return next.toISOString().slice(0, 10);
}

function sessionForm(count: number): string {
  return plural(count, {
    one: t("vpn.activity.session.one"), few: t("vpn.activity.session.few"),
    many: t("vpn.activity.session.many"), other: t("vpn.activity.session.other"),
  });
}

/**
 * One cell per calendar day of the report window (office time zone, as the
 * engine counts days). A day without sessions is empty only when the
 * employee's session list is complete; otherwise it is "unknown".
 */
export function activityDays(sessions: Session[], window: ActivityWindow, detailsIncomplete: boolean): ActivityDay[] {
  const first = window.local_from_date;
  const last = window.local_to_date;
  if (!first || !last || first > last) return [];
  const zone = window.timezone || "UTC";
  const byDay = new Map<string, Session[]>();
  for (const session of sessions) {
    if (!session.started_at_utc) continue;
    const date = localDate(session.started_at_utc, zone);
    if (!date || date < first || date > last) continue;
    byDay.set(date, [...(byDay.get(date) ?? []), session]);
  }
  const days: ActivityDay[] = [];
  for (let date = first; date <= last && days.length < MAX_DAYS; date = nextDay(date)) {
    const daySessions = byDay.get(date) ?? [];
    const tone: ActivityDay["tone"] = daySessions.some((session) => session.overlap_violation)
      ? "violation"
      : daySessions.some((session) => session.lifecycle_state !== "closed" || !session.stopped_at_utc)
        ? "pending"
        : daySessions.length ? "confirmed" : detailsIncomplete ? "unknown" : "empty";
    days.push({ date, sessions: daySessions, tone });
  }
  return days;
}

function getToneText(tone: ActivityDay["tone"]): string {
  switch (tone) {
    case "confirmed": return t("vpn.activity.tone.confirmed");
    case "pending": return t("vpn.activity.tone.pending");
    case "violation": return t("vpn.activity.tone.violation");
    case "unknown": return t("vpn.activity.tone.unknown");
    case "empty": return t("vpn.activity.tone.empty");
  }
}

const dayLabel = (date: string) => formatDateTime(date, "UTC", { withTime: false, withYear: false });

/** Per-day VPN activity of one employee (cell component `vpn.activity-strip`). */
export function VpnActivityStrip({ row, window }: { row: Row; window?: ActivityWindow }) {
  const [openDay, setOpenDay] = useState<ActivityDay | null>(null);
  const sessions = Array.isArray(row.sessions) ? (row.sessions as Session[]) : [];
  const days = window ? activityDays(sessions, window, Boolean(row.session_details_has_more)) : [];
  if (!days.length) return <span className="sli-ds-activity__fallback">{sessions.length} {sessionForm(sessions.length)}</span>;
  const placed = new Set(days.flatMap((day) => day.sessions.map((session) => session.session_row_id)));
  const unplaced = sessions.filter((session) => !placed.has(session.session_row_id)).length;
  return <div className="sli-ds-activity" aria-label={t("vpn.activity.aria.strip", { name: String(row.display_name ?? "") })}>
    <span className="sli-ds-activity__edge">{dayLabel(days[0].date)}</span>
    <div className="sli-ds-activity__track" style={{ gridTemplateColumns: `repeat(${days.length}, minmax(0, 1fr))` }}>
      {days.map((day) => {
        const label = `${dayLabel(day.date)}: ${day.sessions.length ? `${day.sessions.length} ${sessionForm(day.sessions.length)}, ` : ""}${getToneText(day.tone)}`;
        const count = day.sessions.length > 1 ? <span className="sli-ds-activity__count" aria-hidden="true">{day.sessions.length}</span> : null;
        return day.sessions.length
          ? <button key={day.date} type="button" className="sli-ds-activity__day" data-tone={day.tone} title={label} aria-label={`${label}. ${t("vpn.activity.openDay")}`}
              onClick={(event) => { event.stopPropagation(); setOpenDay(day); }}>{count}</button>
          : <span key={day.date} className="sli-ds-activity__day" data-tone={day.tone} title={label} role="img" aria-label={label}/>;
      })}
    </div>
    <span className="sli-ds-activity__edge">{dayLabel(days[days.length - 1].date)}</span>
    {unplaced ? <span className="sli-ds-activity__unplaced" title={t("vpn.activity.unplaced")}>+{unplaced}</span> : null}
    {openDay ? <div onClick={(event) => event.stopPropagation()} onKeyDown={(event) => event.stopPropagation()}><VpnDayDrawer row={row} date={openDay.date} sessions={openDay.sessions} sourceDomainId={window?.source_domain_id ?? null} dayTimeZone={window?.timezone} onClose={() => setOpenDay(null)}/></div> : null}
  </div>;
}
