import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { selectedDomain } from "../../app/domain-navigation";
import { withReturnTo } from "../../app/report-v2/legacy";
import { periodBounds, type FilterValues, type PeriodValue } from "../../design-system";
import { localDateTimeToUtc, utcToLocalDateTimeInput } from "../../shared/date-time";
import type { StationHardware } from "./hardware-model";

export const WORKSTATIONS_KEY = "workstations.overview";
export const PAGE_SIZES = [25, 50, 100, 200];
export const EVENT_VIEWS = ["all", "authentication", "groups", "audit", "tasks"] as const;
export const ACTIVITY_TABS = ["important", "programs", "logons", "devices"] as const;
export type ActivityTab = typeof ACTIVITY_TABS[number];
export type StationTab = ActivityTab | "hardware" | "events" | "collection";
export const STATION_SEVERITIES = ["high", "medium", "low"] as const;
export type StationSeverity = typeof STATION_SEVERITIES[number];
export type EventView = typeof EVENT_VIEWS[number];
export type Row = Record<string, unknown>;
export const record = (value: unknown): Row => value && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
export const sourceText = (value: unknown): string | null => typeof value === "string" && value.trim() && !["-", "—"].includes(value.trim()) ? value : null;
const scalar = (value: unknown) => sourceText(value) ?? (typeof value === "number" && Number.isFinite(value) ? String(value) : null);
const positiveId = (value: unknown) => typeof value === "number" && !Number.isSafeInteger(value) ? null
  : /^[1-9]\d*$/.test(String(value)) ? String(value) : null;
const count = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
const timestamp = (value: unknown) => typeof value === "string" && /(?:Z|[+-]\d\d:\d\d)$/i.test(value)
  && Number.isFinite(Date.parse(value)) ? value : null;

export type Station = {
  station_id: string; agent_key: string | null; agent_version: string | null; transport_agent_id: string | null; source_instance_id: string | null;
  display_name: string | null; host_name: string | null; domain_id: string | null; domain_name: string | null;
  server_id: string | null; operating_system: string | null; operating_system_version: string | null; model: string | null;
  metadata_observed_at: string | null; agent_status: string | null; last_seen: string | null; last_logon_utc: string | null;
  policy_revision: string | null; applied_policy_revision: string | null;
  collection_state: "enabled" | "disabled" | "unbound";
  profile: { event_ids: number[]; channels: string[]; state: "supported" | "unsupported" | "unbound" };
  journal_available: boolean;
};

export function stationRows(items: Row[]): Station[] {
  return items.map(row => {
    const profile = record(row.profile);
    if (typeof row.station_id !== "string" || !row.station_id
      || (!sourceText(row.agent_key) && !(row.agent_key === null && /^ws:ad:[1-9]\d*$/.test(row.station_id)))
      || !["enabled", "disabled", "unbound"].includes(String(row.collection_state))
      || !["supported", "unsupported", "unbound"].includes(String(profile.state))) throw new Error("workstation_response_invalid");
    return {
      station_id: row.station_id, agent_key: sourceText(row.agent_key), agent_version: sourceText(row.agent_version),
      transport_agent_id: sourceText(row.transport_agent_id),
      source_instance_id: sourceText(row.source_instance_id), display_name: sourceText(row.display_name), host_name: sourceText(row.host_name),
      domain_id: positiveId(row.domain_id), domain_name: sourceText(row.domain_name), server_id: positiveId(row.server_id),
      operating_system: sourceText(row.operating_system), operating_system_version: sourceText(row.operating_system_version),
      model: sourceText(row.model),
      metadata_observed_at: timestamp(row.metadata_observed_at), agent_status: sourceText(row.agent_status), last_seen: timestamp(row.last_seen),
      last_logon_utc: timestamp(row.last_logon_utc),
      policy_revision: scalar(row.policy_revision), applied_policy_revision: scalar(row.applied_policy_revision),
      collection_state: row.collection_state as Station["collection_state"],
      profile: { state: profile.state as Station["profile"]["state"],
        event_ids: Array.isArray(profile.event_ids) ? profile.event_ids.filter((id): id is number => typeof id === "number" && Number.isInteger(id) && id > 0 && id <= 65535) : [],
        channels: Array.isArray(profile.channels) ? profile.channels.filter((item): item is string => typeof item === "string" && item.length > 0) : [] },
      journal_available: row.journal_available === true,
    };
  });
}

export type StationEvent = {
  key: string; id: string | null; code: string | null; title: string | null; first: string | null; last: string | null;
  count: number | null; group: boolean; expandable: boolean; account: string | null; initiator: string | null;
  computer: string | null; address: string | null; result: string | null; channel: string | null; logonType: string | null;
  imagePath: string | null; parentImagePath: string | null; commandLine: string | null;
  deviceName: string | null; deviceClass: string | null;
  findingId: string | null; severity: string | null; importance: StationSeverity | null; evidenceAvailable: boolean;
};

/** Keep native saved groups intact; their representative ID is never an individual source event. */
export function eventRows(items: Row[]): StationEvent[] {
  const anonymousRows = new Map<string, number>();
  return items.map(row => {
    const id = positiveId(row.id);
    const summary = sourceText(row.summary_key), day = sourceText(row.day);
    const time = timestamp(row.time_created_utc);
    let key = id ?? (summary && day ? `${day}:${summary}` : null);
    if (!key && time) {
      const occurrence = (anonymousRows.get(time) ?? 0) + 1;
      anonymousRows.set(time, occurrence);
      key = `${time}:${occurrence}`;
    }
    if (!key) throw new Error("workstation_event_invalid");
    const messages = record(row.presentation_messages);
    const total = count(row.event_count);
    const group = row.journal_expandable === true || total !== null && total > 1 || Boolean(summary && day);
    const findingId = positiveId(row.journal_finding_id);
    const code = scalar(row.event_id), details = record(row.workstation_event);
    const process = code === "4688", device = code === "6416";
    return { key, id, code,
      title: record(messages.title_text).code === "events.unknown_type" ? null : sourceText(row.title_text),
      first: timestamp(row.first_seen_utc) ?? time,
      last: timestamp(row.last_seen_utc) ?? time, count: total,
      group, expandable: row.journal_expandable === true,
      account: (process ? sourceText(details.account) : null)
        ?? (record(messages.participant).code === "events.participant_unknown" ? null : sourceText(row.participant)),
      initiator: process ? sourceText(details.initiator) : sourceText(row.on_behalf),
      computer: sourceText(row.journal_computer), address: sourceText(row.ip_address),
      imagePath: process ? sourceText(details.image_path) : null,
      parentImagePath: process ? sourceText(details.parent_image_path) : null,
      commandLine: process ? sourceText(details.command_line) : null,
      deviceName: device ? sourceText(details.device_name) : null,
      deviceClass: device ? sourceText(details.device_class) : null,
      result: sourceText(row.journal_result), channel: sourceText(row.channel), logonType: scalar(row.logon_type),
      findingId, severity: findingId && ["critical", "high", "medium", "low"].includes(String(row.journal_severity)) ? String(row.journal_severity) : null,
      importance: STATION_SEVERITIES.find(severity => severity === row.station_importance) ?? null,
      evidenceAvailable: row.journal_evidence_available === true && !group && id !== null,
    };
  });
}

export type StationEvents = Pick<ReportResultDto, "state" | "items" | "has_more" | "next_cursor" | "filtered_count" | "window"> & {
  journal_event_count?: number | null; coverage?: ReportResultDto["coverage"]; limitations?: ReportResultDto["limitations"];
};
export type ActivityInterval = { first: string; last: string };
export type StationFact = ActivityInterval & {
  fact: "writable_program" | "service_outside_system" | "local_admin_added" | "audit_policy_changed"
    | "security_log_cleared" | "new_program" | "new_usb_storage" | "logon_failure_burst" | "remote_logon"
    | "service_installed" | "local_account_created";
  severity: StationSeverity; object: string | null; count: number;
};
export type StationProgram = ActivityInterval & { name: string; path: string; writable: boolean; count: number; users: string[]; severity?: StationSeverity | null };
export type StationLogon = { account: string | null; type: string | null; last: string; count: number; failures: number };
export type StationDevice = ActivityInterval & { class: string | null; name: string | null };
export type StationActivity = { notable: StationFact[]; programs: StationProgram[]; logons: StationLogon[]; devices: StationDevice[] };
export type StationDetailResult = ReportResultDto & { detail?: {
  station: Row; events: StationEvents; activity?: StationActivity | null; hardware?: StationHardware | null;
  related: { journal: { allowed: boolean; params?: Record<string, unknown> }; problems: { allowed: boolean } };
} };

export function pageSize(value: unknown, maximum = 200): number {
  const sizes = PAGE_SIZES.filter(size => size <= maximum);
  const requested = Number(value) || 50;
  return sizes.includes(requested) ? requested : sizes.filter(size => size <= requested).at(-1) ?? sizes[0] ?? 25;
}

export function paging(rows: Row[] | undefined) {
  const row = rows?.[0];
  return { start: typeof row?.start === "number" && Number.isSafeInteger(row.start) && row.start > 0 ? row.start : 1,
    hasPrevious: row?.has_previous === true,
    previousCursor: typeof row?.previous_cursor === "string" ? row.previous_cursor : null };
}

export function initialSearch(input: string, now = new Date()): URLSearchParams {
  const next = new URLSearchParams(input);
  if (next.get("period") === "custom" || next.get("from") && next.get("to")) { next.set("period", "custom"); return next; }
  const preset = ["24h", "7d", "30d"].includes(next.get("period") ?? "") ? next.get("period")! : "7d";
  const bounds = periodBounds({ preset: preset as PeriodValue["preset"] }, now)!;
  next.set("period", "custom"); next.set("from", bounds.from); next.set("to", bounds.to); next.set("ws_preset", preset);
  return next;
}

function exactUtc(value: string, timeZone: string): string | null {
  const fractional = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.(\d{1,3})$/.exec(value);
  if (!fractional) return localDateTimeToUtc(value, timeZone);
  const seconds = localDateTimeToUtc(fractional[1], timeZone);
  return seconds ? new Date(Date.parse(seconds) + Number(fractional[2].padEnd(3, "0"))).toISOString() : null;
}

export function exactWindow(search: URLSearchParams, timeZone: string): { from: string; to: string } | null {
  if (!search.get("from") || !search.get("to")) return null;
  try {
    const from = exactUtc(search.get("from")!, timeZone), to = exactUtc(search.get("to")!, timeZone);
    return from && to && from < to && Date.parse(to) - Date.parse(from) <= 90 * 86400_000 ? { from, to } : null;
  } catch { return null; }
}

export function filterValues(search: URLSearchParams, timeZone: string): FilterValues {
  const local = (value: string | null) => {
    if (!value) return undefined;
    if (!/(?:Z|[+-]\d\d:\d\d)$/i.test(value)) return value;
    try { return utcToLocalDateTimeInput(value, timeZone, "millisecond"); } catch { return value; }
  };
  const preset = ["24h", "7d", "30d"].includes(search.get("ws_preset") ?? "") ? search.get("ws_preset") as PeriodValue["preset"] : "custom";
  return { search: search.get("search") ?? "", collection: search.get("collection") ?? "all", view: eventView(search),
    period: { preset, from: local(search.get("from")), to: local(search.get("to")) } };
}

/** Unedited custom boundaries retain their exact instant, including the second occurrence in a DST fold. */
export function appliedFilters(values: FilterValues, current: URLSearchParams, timeZone: string, now = new Date()) {
  const period = values.period as PeriodValue | undefined;
  const patch: Record<string, string | null> = {};
  for (const key of ["search", "collection", "view"]) if (key in values) patch[key] = typeof values[key] === "string" ? values[key] : null;
  if (!period) return patch;
  patch.period = "custom";
  if (period.preset !== "custom") {
    const bounds = periodBounds(period, now);
    patch.from = bounds?.from ?? null; patch.to = bounds?.to ?? null; patch.ws_preset = period.preset;
    return patch;
  }
  const displayed = filterValues(current, timeZone).period as PeriodValue;
  for (const key of ["from", "to"] as const) {
    if (period[key] === displayed[key]) patch[key] = current.get(key);
    else { try { patch[key] = period[key] ? exactUtc(period[key]!, timeZone) ?? period[key]! : null; } catch { patch[key] = period[key] ?? null; } }
  }
  patch.ws_preset = null;
  return patch;
}

export const eventView = (search: URLSearchParams): EventView => EVENT_VIEWS.find(view => view === search.get("view")) ?? "all";
export function stationTab(search: URLSearchParams): StationTab {
  const tab = search.get("station_tab");
  return ACTIVITY_TABS.find(key => key === tab)
    ?? (tab === "collection" || tab === "hardware" ? tab : tab === "events" || search.has("event") || search.has("event_cursor") || search.has("program") ? "events" : "important");
}

/** Browser navigation fields never enter either native API route. The registry supplies the business allowlist. */
export function requestParams(search: URLSearchParams, timeZone: string, definition: ReportDefinitionDto, detail = false): URLSearchParams | null {
  const bounds = exactWindow(search, timeZone);
  if (!bounds) return null;
  const allowed = new Set(definition.params.map(param => param.key));
  const params = new URLSearchParams({ period: "custom", from: bounds.from, to: bounds.to, tz: timeZone });
  const domain = selectedDomain(search.toString());
  if (domain && allowed.has("domain")) params.set("domain", domain);
  for (const key of detail ? ["source_instance_id"] : ["search", "collection", "source_instance_id"]) {
    const value = search.get(key);
    if (allowed.has(key) && value) params.set(key, value);
  }
  params.set("limit", String(pageSize(search.get("limit"), definition.limits.max)));
  if (detail) {
    if (allowed.has("view")) params.set("view", eventView(search));
    if (allowed.has("event_limit")) params.set("event_limit", String(pageSize(search.get("event_limit") ?? search.get("limit"), definition.limits.max)));
    if (allowed.has("event_cursor") && search.get("event_cursor")) params.set("event_cursor", search.get("event_cursor")!);
    if (allowed.has("program") && search.get("program")) params.set("program", search.get("program")!);
  } else if (search.get("cursor")) params.set("cursor", search.get("cursor")!);
  return params;
}

export function eventHistory(search: URLSearchParams): Array<string | null> {
  try {
    const values: unknown = JSON.parse(search.get("event_history") ?? "[]");
    return Array.isArray(values) && values.length <= 200 && values.every(value => value === null || typeof value === "string" && value.length <= 4096) ? values : [];
  } catch { return []; }
}
export function eventPage(search: URLSearchParams): number {
  const page = Number(search.get("event_page"));
  return Number.isSafeInteger(page) && page >= 0 ? page : 0;
}
export const resetEvents = { event_cursor: null, event_history: null, event_page: null, event: null };
export const closeStation = { station: null, station_tab: null, station_return: null, event_limit: null, view: null, program: null, ...resetEvents };

export function patchedSearch(search: URLSearchParams, patch: Record<string, string | null>) {
  const next = new URLSearchParams(search);
  for (const [key, value] of Object.entries(patch)) value === null || value === "" ? next.delete(key) : next.set(key, value);
  return next;
}
export const localHref = (search: URLSearchParams, path = window.location.pathname) => `${path}${search.size ? `?${search}` : ""}`;

export function fleetReturnHref(search: URLSearchParams, path = window.location.pathname): string {
  const value = search.get("station_return");
  if (value?.startsWith("/app/")) {
    try {
      const url = new URL(value, "https://sli.example.invalid");
      if (url.origin === "https://sli.example.invalid" && ["/app/workstations", "/app/report/workstations.overview"].includes(url.pathname)
        && !url.searchParams.has("station")) return `${url.pathname}${url.search}`;
    } catch { /* A direct link falls back to the current, bounded list context. */ }
  }
  return localHref(patchedSearch(search, closeStation), path);
}

export function journalHref(detail: Pick<NonNullable<StationDetailResult["detail"]>, "related"> | undefined, back: string, row?: StationEvent): string | null {
  if (!detail?.related?.journal?.allowed || !detail.related.journal.params) return null;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(detail.related.journal.params)) if (typeof value === "string" || typeof value === "number") params.set(key, String(value));
  if (row?.expandable && row.id) params.set("expand", row.id);
  return withReturnTo(`/app/report/events.journal?${params}`, back);
}

export function findingHref(row: StationEvent, station: Station, back: string): string | null {
  if (!row.findingId) return null;
  const params = new URLSearchParams({ id: row.findingId });
  if (station.domain_id) params.set("domain", station.domain_id);
  return withReturnTo(`/app/report/security.problems?${params}`, back);
}
export function evidenceHref(row: StationEvent, station: Station, back: string): string | null {
  if (!row.evidenceAvailable || !row.id || row.group) return null;
  const params = new URLSearchParams();
  if (station.domain_id) params.set("domain", station.domain_id);
  return withReturnTo(`/app/events/${row.id}${params.size ? `?${params}` : ""}`, back);
}
