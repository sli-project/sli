import { getLocale, t } from "../i18n";
import { EMPTY_VALUE } from "./format";

export type DisplayTimeZone = "browser" | string;
const UNAVAILABLE_TIME_ZONE_PREFIX = "invalid:";

const LOCAL_DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/;

function partsAt(instantMs: number, timeZone: string) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
  }).formatToParts(new Date(instantMs));
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day), Number(values.hour), Number(values.minute), Number(values.second));
}

export function localDateTimeToUtc(value: string, timeZone: DisplayTimeZone): string | null {
  const match = LOCAL_DATE_TIME.exec(value.trim());
  if (!match) {
    const instant = new Date(value);
    return Number.isNaN(instant.getTime()) ? null : instant.toISOString();
  }
  const [, year, month, day, hour, minute, second = "0"] = match;
  if (timeZone === "browser") {
    const instant = new Date(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second));
    return Number.isNaN(instant.getTime()) ? null : instant.toISOString();
  }
  const desiredWallClock = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second));
  let instantMs = desiredWallClock;
  // Two passes handle zones whose offset at the initial UTC guess differs due
  // to a daylight-saving transition.
  for (let pass = 0; pass < 2; pass += 1) {
    instantMs = desiredWallClock - (partsAt(instantMs, timeZone) - instantMs);
  }
  return new Date(instantMs).toISOString();
}

export function utcToLocalDateTimeInput(value: string | null | undefined, timeZone: DisplayTimeZone): string {
  if (!value) return "";
  const instant = new Date(value);
  if (Number.isNaN(instant.getTime())) return "";
  if (timeZone === "browser") {
    const local = new Date(instant.getTime() - instant.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 16);
  }
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).formatToParts(instant);
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${values.year}-${values.month}-${values.day}T${values.hour}:${values.minute}`;
}

/** Intl locale for the current interface language. */
const intlLocale = () => (getLocale() === "en" ? "en-US" : "ru-RU");

export type DateTimeFormatOptions = { withTime?: boolean; seconds?: boolean; withYear?: boolean; timeOnly?: boolean };

/**
 * The single date/time formatter for the UI.
 * ru: 21.10.2026, 14:05   en: Oct 21, 2026, 2:05 PM (month name, so 10/11 never reads as day/month).
 * An absent value is the empty-value dash; a bad time zone is reported, never silently ignored.
 */
export function formatDateTime(value: string | Date | null | undefined, timeZone: DisplayTimeZone | undefined = "browser", options: DateTimeFormatOptions = {}) {
  const { withTime = true, seconds = false, withYear = true, timeOnly = false } = options;
  if (value === null || value === undefined || value === "") return EMPTY_VALUE;
  const calendarDay = typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value);
  const instant = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(instant.getTime())) return EMPTY_VALUE;
  // A calendar day has no offset. Do not move it to the previous day in a
  // western zone, and do not accept normalized dates such as February 30.
  const sourceDay = typeof value === "string" ? /^(\d{4}-\d{2}-\d{2})(?:T|$)/.exec(value)?.[1] : undefined;
  if (sourceDay && new Date(`${sourceDay}T00:00:00Z`).toISOString().slice(0, 10) !== sourceDay) return EMPTY_VALUE;
  if (calendarDay && !withTime) timeZone = "UTC";
  if (timeZone.startsWith(UNAVAILABLE_TIME_ZONE_PREFIX)) return t("operations.dateTime.zoneUnavailable", { zone: timeZone.slice(UNAVAILABLE_TIME_ZONE_PREFIX.length) });
  const en = getLocale() === "en";
  try {
    return new Intl.DateTimeFormat(intlLocale(), {
      timeZone: timeZone === "browser" ? undefined : timeZone,
      ...(timeOnly ? { hour: "2-digit" as const, minute: "2-digit" as const, hourCycle: "h23" as const } : {
      ...(withYear ? { year: "numeric" as const } : {}), month: en ? "short" : "2-digit", day: en ? "numeric" : "2-digit",
      ...(withTime ? { hour: en ? "numeric" : "2-digit", minute: "2-digit", ...(seconds ? { second: "2-digit" } : {}), hourCycle: en ? "h12" : "h23" } : {}),
      }),
    }).format(instant);
  } catch {
    return t("operations.dateTime.zoneUnavailable", { zone: timeZone });
  }
}

export const formatDate = (value: string | Date | null | undefined, timeZone: DisplayTimeZone | undefined = "browser") =>
  formatDateTime(value, timeZone, { withTime: false });

export function formatClockWithOffset(instant: Date, timeZone: DisplayTimeZone) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: timeZone === "browser" ? undefined : timeZone,
    hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZoneName: "shortOffset",
  }).formatToParts(instant);
  const offset = parts.find((part) => part.type === "timeZoneName")?.value.slice(3) || "+0";
  const time = parts.filter((part) => part.type === "hour" || part.type === "minute").map((part) => part.value).join(":");
  return { time, zone: `UTC${offset}` };
}

/** "3 days ago" / "3 дня назад" (days, or hours/minutes for fresh values). */
export function formatRelative(value: string | Date | null | undefined, { now = Date.now(), daysOnly = false }: { now?: number; daysOnly?: boolean } = {}): string {
  if (value === null || value === undefined || value === "") return EMPTY_VALUE;
  const ms = (value instanceof Date ? value : new Date(value)).getTime();
  if (Number.isNaN(ms)) return EMPTY_VALUE;
  const rtf = new Intl.RelativeTimeFormat(intlLocale(), { numeric: "auto" });
  const diff = (ms - now) / 1000;
  const abs = Math.abs(diff);
  if (!daysOnly && abs < 3600) return rtf.format(Math.trunc(diff / 60), "minute");
  if (!daysOnly && abs < 86_400) return rtf.format(Math.trunc(diff / 3600), "hour");
  return rtf.format(Math.trunc(diff / 86_400), "day");
}

/** Machine-readable calendar day YYYY-MM-DD in a zone (chart buckets, filters); not for display. */
export function dayKey(value: string | Date, timeZone: DisplayTimeZone | undefined): string | null {
  const instant = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(instant.getTime())) return null;
  return new Intl.DateTimeFormat("en-CA", { timeZone: timeZone === "browser" ? undefined : timeZone, year: "numeric", month: "2-digit", day: "2-digit" }).format(instant);
}

export function isValidTimeZone(timeZone: string): boolean {
  try { new Intl.DateTimeFormat("en", { timeZone }); return true; } catch { return false; }
}

export const browserTimeZone = (): string => Intl.DateTimeFormat().resolvedOptions().timeZone;

/** Short weekday name (Mon, Tue…) in the UI locale for a UTC calendar day. */
export const shortWeekday = (day: Date): string =>
  new Intl.DateTimeFormat(intlLocale(), { weekday: "short", timeZone: "UTC" }).format(day);

/** Wall-clock parts of an instant in a zone (24h), for exact-instant arithmetic. */
export function zonedParts(instant: Date, timeZone: DisplayTimeZone): Record<string, string> {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: timeZone === "browser" ? undefined : timeZone,
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
  }).formatToParts(instant);
  return Object.fromEntries(parts.map((part) => [part.type, part.value]));
}
