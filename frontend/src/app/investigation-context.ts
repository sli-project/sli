import { isValidTimeZone } from "../shared/date-time";
import { t } from "../i18n";

/** Selection travels between views; it never grants access to an object. */
export type InvestigationNavigationContext = {
  event_db_id?: string;
  entity_id?: string;
  q?: string;
  scope?: "important" | "all";
  time_from?: string;
  time_to?: string;
  timezone?: string;
};

export type InvestigationDisplayTimeZone = { timeZone: string; available: boolean };
const UNAVAILABLE_TIME_ZONE_PREFIX = "invalid:";
const SAFE_RETURN_PATH = /^\/app\/(?:security-events-report|report\/[a-z0-9][a-z0-9_.-]{1,79}|events(?:\/\d+)?|entities(?:\/\d+)?|objects|investigations(?:\/\d+)?)(?:[?#]|$)/;
export const RELATIVE_NAVIGATION_ORIGIN = "https://sli.example.invalid";

function unavailableTimeZone(value: string): InvestigationDisplayTimeZone {
  return { timeZone: `${UNAVAILABLE_TIME_ZONE_PREFIX}${value || t("investigations.context.notSpecified")}`, available: false };
}

/** A return address is presentation context, never a capability or an open redirect. */
export function safeInvestigationReturnTo(value: string | null | undefined, fallback: string): string {
  const candidate = value?.trim() ?? "";
  if (!candidate || candidate.includes("\\") || /[\u0000-\u001f\u007f]/.test(candidate)) return fallback;
  if (!SAFE_RETURN_PATH.test(candidate)) return fallback;
  try {
    const parsed = new URL(candidate, RELATIVE_NAVIGATION_ORIGIN);
    if (parsed.origin !== RELATIVE_NAVIGATION_ORIGIN) return fallback;
  } catch {
    return fallback;
  }
  return candidate;
}

export function navigationHrefWithReturnTo(href: string, returnTo: string): string {
  const target = new URL(href, RELATIVE_NAVIGATION_ORIGIN);
  target.searchParams.set("return_to", safeInvestigationReturnTo(returnTo, "/app/events"));
  return `${target.pathname}${target.search}${target.hash}`;
}

const keys = ["event_db_id", "entity_id", "q", "scope", "time_from", "time_to", "timezone"] as const;
const apiKeys = ["event_db_id", "entity_id", "q", "scope", "time_from", "time_to", "timezone"] as const;

type ParsedTime = { form: "date" | "local" | "absolute"; value: number; microsecondRemainder: number };

const timePattern = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,6}))?)?(Z|[+-]\d{2}:?\d{2})?)?$/;

function civilTimestamp(year: number, month: number, day: number, hour = 0, minute = 0, second = 0, milliseconds = 0): number {
  const parsed = new Date(0);
  parsed.setUTCFullYear(year, month - 1, day);
  parsed.setUTCHours(hour, minute, second, milliseconds);
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day
    || parsed.getUTCHours() !== hour || parsed.getUTCMinutes() !== minute || parsed.getUTCSeconds() !== second
    || parsed.getUTCMilliseconds() !== milliseconds) throw new Error("invalid_time");
  return parsed.getTime();
}

function timeValue(value: string): ParsedTime {
  const match = timePattern.exec(value);
  if (!match) throw new Error("invalid_time");
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, millisecondsText, offset] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  if (hourText === undefined || minuteText === undefined) {
    return { form: "date", value: civilTimestamp(year, month, day), microsecondRemainder: 0 };
  }
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = secondText === undefined ? 0 : Number(secondText);
  const microseconds = millisecondsText === undefined ? 0 : Number(millisecondsText.padEnd(6, "0"));
  const milliseconds = Math.floor(microseconds / 1_000);
  const microsecondRemainder = microseconds % 1_000;
  const civil = civilTimestamp(year, month, day, hour, minute, second, milliseconds);
  if (!offset) return { form: "local", value: civil, microsecondRemainder };
  if (offset === "Z") return { form: "absolute", value: civil, microsecondRemainder };
  const offsetMatch = /^([+-])(\d{2}):?(\d{2})$/.exec(offset);
  if (!offsetMatch) throw new Error("invalid_time");
  const offsetMinutes = Number(offsetMatch[2]) * 60 + Number(offsetMatch[3]);
  if (Number(offsetMatch[2]) > 23 || Number(offsetMatch[3]) > 59) throw new Error("invalid_time");
  return { form: "absolute", value: civil + (offsetMatch[1] === "+" ? -offsetMinutes : offsetMinutes) * 60_000, microsecondRemainder };
}

function provablyReversed(from: ParsedTime, to: ParsedTime): boolean {
  if (from.form !== to.form) return false;
  if (to.form === "date") return from.value >= to.value + 86_400_000;
  return from.value > to.value || (from.value === to.value && from.microsecondRemainder >= to.microsecondRemainder);
}

export function investigationContext(parameters: URLSearchParams): InvestigationNavigationContext {
  const context: InvestigationNavigationContext = {};
  for (const key of keys) {
    const values = parameters.getAll(key);
    if (values.length > 1) throw new Error(`duplicate_${key}`);
    const value = values[0]?.trim();
    if ((key === "event_db_id" || key === "entity_id") && values.length === 1 && !value) {
      throw new Error(`invalid_${key}`);
    }
    if (!value) continue;
    if ((key === "event_db_id" || key === "entity_id")
      && (!/^[1-9]\d*$/.test(value) || !Number.isSafeInteger(Number(value)))) {
      throw new Error(`invalid_${key}`);
    }
    if (key === "scope") {
      if (value !== "all" && value !== "important") throw new Error("invalid_scope");
      context.scope = value;
    } else {
      context[key] = value;
    }
  }
  const timeFrom = context.time_from ? timeValue(context.time_from) : null;
  const timeTo = context.time_to ? timeValue(context.time_to) : null;
  if (timeFrom !== null && timeTo !== null && provablyReversed(timeFrom, timeTo)) {
    throw new Error("invalid_time_range");
  }
  return context;
}

/** Any admitted selection or filter means the user requested the investigation workspace. */
export function investigationWorkspaceRequested(context: InvestigationNavigationContext): boolean {
  return Boolean(
    context.q || context.event_db_id || context.entity_id || context.time_from
    || context.time_to || context.timezone || context.scope
  );
}

/** The navigation context controls presentation only when it carries a valid IANA zone. */
export function investigationDisplayTimeZone(context: InvestigationNavigationContext | null | undefined, fallback: string): InvestigationDisplayTimeZone {
  const timeZone = context?.timezone ?? fallback;
  if (context?.timezone === "browser") return unavailableTimeZone(timeZone);
  if (timeZone === "browser") return { timeZone, available: true };
  try {
    if (!isValidTimeZone(timeZone)) throw new Error("invalid");
    return { timeZone, available: true };
  } catch {
    return unavailableTimeZone(timeZone);
  }
}

export function investigationDisplayTimeZoneFromSearch(search: string, fallback: string): InvestigationDisplayTimeZone {
  const parameters = new URLSearchParams(search);
  try {
    return investigationDisplayTimeZone(investigationContext(parameters), fallback);
  } catch {
    const requested = parameters.getAll("timezone").map((value) => value.trim());
    if (requested.length) return unavailableTimeZone(requested.join(", "));
    return unavailableTimeZone(t("investigations.context.contextParameters"));
  }
}

export function investigationParameters(context: InvestigationNavigationContext): URLSearchParams {
  const parameters = new URLSearchParams();
  for (const key of keys) {
    const value = context[key];
    if (value) parameters.set(key, value);
  }
  return parameters;
}

export function investigationSearch(search: string, selection: Partial<InvestigationNavigationContext>): Record<string, string> {
  const context = { ...investigationContext(new URLSearchParams(search)), ...selection };
  return Object.fromEntries(investigationParameters(investigationContext(investigationParameters(context))));
}

/** TanStack Router serializes numeric-looking strings as JSON values; IDs must stay numeric in its search object. */
export function investigationRouterSearch(context: InvestigationNavigationContext): Record<string, string | number> {
  const admitted = investigationContext(investigationParameters(context));
  const search: Record<string, string | number> = {};
  for (const [key, value] of investigationParameters(admitted)) {
    search[key] = key === "event_db_id" || key === "entity_id" ? Number(value) : value;
  }
  return search;
}

/** Parameters supported by the server workspace contract; identity search is not implied. */
export function investigationApiParameters(context: InvestigationNavigationContext): URLSearchParams {
  const parameters = new URLSearchParams();
  for (const key of apiKeys) {
    const value = context[key];
    if (value) parameters.set(key, value);
  }
  return parameters;
}

/** Exact entity reads never discard one half of a supplied time range. */
export function entityWorkspaceApiParameters(search: string, limit = 50): URLSearchParams {
  const context = investigationContext(new URLSearchParams(search));
  if (Boolean(context.time_from) !== Boolean(context.time_to)) {
    throw new Error("entity_time_context_requires_both_bounds");
  }
  const parameters = new URLSearchParams({ limit: String(limit) });
  if (context.time_from && context.time_to) {
    parameters.set("time_from", context.time_from);
    parameters.set("time_to", context.time_to);
  }
  if (context.timezone) parameters.set("timezone", context.timezone);
  return parameters;
}

export function investigationQueryKey(context: InvestigationNavigationContext): readonly ["investigation", string] {
  return ["investigation", investigationApiParameters(context).toString()];
}
