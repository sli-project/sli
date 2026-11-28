import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { periodBounds, type FilterField, type FilterValues, type PeriodValue } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { apiParams, valuesReady } from "../../app/report-v2/state";
import { localDateTimeToUtc, utcToLocalDateTimeInput } from "../../shared/date-time";

export const FILE_AUDIT_TABS = ["overview", "actions", "mass-operations", "permission-changes",
  "access-denials", "out-of-hours", "permissions", "audit-state"] as const;
export type FileAuditTab = typeof FILE_AUDIT_TABS[number];
export const isFileAuditReport = (key: string) => FILE_AUDIT_TABS.some((tab) => key === `file-audit.${tab}`);
export const tabTitle = (tab: FileAuditTab) => t(`file-audit.tabs.${tab}` as MessageKey);
export const FILE_AUDIT_PAGE_SIZES = [25, 50, 100, 200];
export const fileAuditPageSizes = (maximum: number) => FILE_AUDIT_PAGE_SIZES.filter(size => size <= maximum);

export function fileAuditPageSize(value: unknown, maximum = 200): number {
  const sizes = fileAuditPageSizes(maximum);
  const requested = Number(value) || 50;
  return sizes.includes(requested) ? requested : sizes.filter(size => size <= requested).at(-1) ?? sizes[0] ?? 50;
}

export type FileServerView = FileAuditTab;
export const ACTION_FILTERS = ["all", "delete", "changes", "permission-changes", "access-denials", "out-of-hours"] as const;
export type ActionFilter = typeof ACTION_FILTERS[number];

export const FILE_ACTIVITY_VIEWS = ["actions", "mass-operations", "permission-changes", "access-denials", "out-of-hours"] as const;
export type FileActivityView = typeof FILE_ACTIVITY_VIEWS[number];
export const isFileActivityView = (view: FileServerView): view is FileActivityView =>
  FILE_ACTIVITY_VIEWS.some(activity => activity === view);

type SelectOptions = Extract<FilterField, { kind: "select" }>["options"];
export function fileAuditFields(view: FileServerView, servers: SelectOptions = [], shares: SelectOptions = []): FilterField[] {
  if (view === "overview") return [
    { key: "path_search", label: t("file-audit.overview.search"), placeholder: t("file-audit.overview.search"), kind: "text", immediate: true },
  ];
  if (!isFileActivityView(view)) return [];
  return [
    { key: "source_instance_id", label: t("file-audit.workspace.server"), kind: "select", options: servers },
    { key: "share", label: t("file-audit.workspace.resource_path"), kind: "select", options: shares },
    ...(view === "actions" ? [{ key: "operation", label: t("file-audit.activity.operation"), kind: "select" as const, options: [
      { value: "", label: t("filters.any") },
      ...(["read", "write", "delete", "rename"] as const).map(value => ({
        value, label: t(`reports.v2.file-audit.actions.columns.operation.labels.${value}`),
      })),
      { value: "permissions", label: t("file-audit.screen.permission_change") },
      { value: "access_denied", label: t("file-audit.screen.access_denied") },
    ] }] : []),
    { key: "account_search", label: t("file-audit.screen.account_search"), placeholder: t("file-audit.screen.account_search"), kind: "text", immediate: true },
    ...(view !== "mass-operations" ? [
      { key: "path_search", label: t("file-audit.screen.path_search"), placeholder: t("file-audit.screen.path_search"), kind: "text" as const, immediate: true },
      { key: "include_nested", label: t("file-audit.activity.nested"), kind: "checkbox" as const, onValue: "true", offValue: "false" },
    ] : []),
  ];
}

export function fileAuditParams(definition: ReportDefinitionDto, values: FilterValues, timeZone: string, cursor?: string | null, anchor = new Date(), limit = 50) {
  const period = values.period as PeriodValue | undefined;
  // Compare custom bounds after conversion, including external UTC offsets.
  if (!valuesReady(definition, period?.preset === "custom" ? { ...values, period: { preset: "24h" } } : values)) return null;
  const params = apiParams(definition, values, { timeZone, cursor, limit: fileAuditPageSize(limit, definition.limits.max) });
  for (const key of ["source_instance_id", "device_id"]) {
    const value = values[key];
    if (typeof value === "string" && value) params.set(key, value);
  }
  for (const key of ["path_search", "account_search"]) {
    const value = params.get(key)?.trim();
    if (value) params.set(key, Array.from(value).slice(0, key === "path_search" ? 4096 : 256).join(""));
    else params.delete(key);
  }
  if (!period || !["24h", "7d", "30d", "custom"].includes(period.preset)) return null;
  if (period?.preset === "custom") {
    if (!period.from || !period.to) return null;
    try {
      const from = exactUtc(period.from, timeZone), to = exactUtc(period.to, timeZone);
      if (!from || !to || from >= to) return null;
      params.set("from", from); params.set("to", to);
    } catch { return null; }
  } else {
    const bounds = periodBounds(period, anchor);
    if (!bounds) return null;
    params.set("period", "custom"); params.set("from", bounds.from); params.set("to", bounds.to);
  }
  return params;
}

function exactUtc(value: string, timeZone: string): string | null {
  const fractional = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.(\d{1,3})$/.exec(value);
  if (!fractional) return localDateTimeToUtc(value, timeZone);
  const seconds = localDateTimeToUtc(fractional[1], timeZone);
  return seconds ? new Date(Date.parse(seconds) + Number(fractional[2].padEnd(3, "0"))).toISOString() : null;
}

/** datetime-local cannot display a UTC suffix. Retain full precision in the local editor. */
export function fileAuditFilterValues(values: FilterValues, timeZone: string): FilterValues {
  const period = values.period as PeriodValue | undefined;
  if (period?.preset !== "custom") return values;
  const local = (value?: string) => {
    if (!value || !/(?:Z|[+-]\d\d:\d\d)$/i.test(value)) return value;
    const instant = new Date(value);
    if (!Number.isFinite(instant.getTime())) return value;
    try {
      return utcToLocalDateTimeInput(value, timeZone, "millisecond");
    } catch { return value; }
  };
  return { ...values, period: { ...period, from: local(period.from), to: local(period.to) } };
}

/** An unchanged external boundary keeps its exact UTC instant, also across a DST fold. */
export function appliedFileAuditValues(next: FilterValues, current: FilterValues, timeZone: string): FilterValues {
  const period = next.period as PeriodValue | undefined;
  if (period?.preset !== "custom") return next;
  const previous = current.period as PeriodValue | undefined;
  const displayed = fileAuditFilterValues(current, timeZone).period as PeriodValue | undefined;
  const bound = (key: "from" | "to") => {
    const value = period[key] === displayed?.[key] ? previous?.[key] : period[key];
    if (!value) return value;
    try { return exactUtc(value, timeZone) ?? value; } catch { return value; }
  };
  return { ...next, period: { preset: "custom", from: bound("from"), to: bound("to") } };
}

export type FileAuditRow = Record<string, unknown>;

/** A share label or local path is not a source identity. */
export function fileAuditShare(row: FileAuditRow): string | null {
  if ([row.agent_id, row.source_instance_id, row.collection_scope_id].every(value => typeof value === "string" && value.length > 0))
    return JSON.stringify([row.agent_id, row.source_instance_id, row.collection_scope_id]);
  return null;
}

/** Drill-downs carry the already resolved time bounds and exact authorized root. */
export function fileAuditHref(tab: FileAuditTab, params: URLSearchParams, row?: FileAuditRow, extra: Record<string, string | null> = {}): string {
  const query = new URLSearchParams(params);
  for (const key of ["cursor", "detail_row", "snapshot_id", "compare_snapshot_id", "object_path", "view", "page_index"]) query.delete(key);
  if (tab !== "overview") query.delete("deviations_only");
  if (tab !== "overview" && tab !== "actions") query.delete("path_search");
  query.set("tab", tab);
  const share = row ? fileAuditShare(row) : null;
  if (share) { query.delete("share"); query.append("share", share); }
  if (typeof row?.source_instance_id === "string") query.set("source_instance_id", row.source_instance_id);
  if (typeof row?.path === "string") query.set("path", row.path);
  if (tab === "permissions") {
    query.set("view", "objects");
    if (typeof row?.snapshot_id === "string") query.set("snapshot_id", row.snapshot_id);
  }
  if (tab === "permission-changes") query.set("operation", "permissions");
  for (const [key, value] of Object.entries(extra)) value === null ? query.delete(key) : query.set(key, value);
  return `/app/report/file-audit.${tab}?${query}`;
}

/** Only report-local return links are accepted from a deep link. */
export function fileAuditReturnHref(value: string | null): string | null {
  if (!value?.startsWith("/app/report/file-audit.")) return null;
  try {
    const url = new URL(value, "https://sli.example.invalid");
    return url.origin === "https://sli.example.invalid" && isFileAuditReport(url.pathname.slice("/app/report/".length))
      ? `${url.pathname}${url.search}${url.hash}` : null;
  } catch { return null; }
}
