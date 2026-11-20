import { dayKey } from "../shared/date-time";
import type { ChartSpec } from "../design-system";
import { t } from "../i18n";

type TimelineEvent = { time_utc?: string | null; label?: string | null; event_id?: number | null };

const MAX_SERIES = 5;
const MAX_FILLED_DAYS = 92;
function getOthers(): string { return t("entities.timeline.others"); }

function localDay(value: string, timeZone: string | undefined): string | null {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  // en-CA formats as YYYY-MM-DD, the day format the chart recognises.
  return dayKey(date, timeZone);
}

function nextDay(day: string): string {
  const date = new Date(`${day}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + 1);
  return date.toISOString().slice(0, 10);
}

function eventName(event: TimelineEvent): string {
  return event.label || (event.event_id ? `Event ID ${event.event_id}` : t("entities.timeline.eventFallback"));
}

/**
 * Events per local day, stacked by the most frequent event kinds (the rest are
 * one "others" series). Built only from the rows already loaded for the card,
 * so it describes that bounded sample, not the entity's full history.
 */
export function entityEventTimeline(events: readonly TimelineEvent[], timeZone: string | undefined): ChartSpec | null {
  const OTHERS = getOthers();
  const counts = new Map<string, Map<string, number>>();
  const totals = new Map<string, number>();
  for (const event of events) {
    const day = event.time_utc ? localDay(event.time_utc, timeZone) : null;
    if (!day) continue;
    const name = eventName(event);
    totals.set(name, (totals.get(name) ?? 0) + 1);
    const perDay = counts.get(day) ?? new Map<string, number>();
    perDay.set(name, (perDay.get(name) ?? 0) + 1);
    counts.set(day, perDay);
  }
  if (!counts.size) return null;
  const top = [...totals.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, MAX_SERIES).map(([name]) => name);
  const present = [...counts.keys()].sort();
  const days: string[] = [];
  for (let day = present[0]; days.length <= MAX_FILLED_DAYS && day <= present[present.length - 1]; day = nextDay(day)) days.push(day);
  const axis = days.length > MAX_FILLED_DAYS ? present : days;
  const names = totals.size > top.length ? [...top, OTHERS] : top;
  const series = names.map((name) => ({
    name,
    points: axis.map((day) => {
      const perDay = counts.get(day);
      if (!perDay) return { x: day, y: 0 };
      const value = name === OTHERS
        ? [...perDay.entries()].filter(([key]) => !top.includes(key)).reduce((sum, [, count]) => sum + count, 0)
        : perDay.get(name) ?? 0;
      return { x: day, y: value };
    }),
  }));
  return { kind: "timeseries", series, stacked: true };
}
