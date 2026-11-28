import type { FilterField, FilterValues, PeriodPreset, PeriodValue, SortState } from "../../design-system";
import type { ReportColumnDto, ReportDefinitionDto, ReportOption } from "../../api/report-v2-types";
import { reportEnumText } from "../../i18n/report-metadata";
import { t } from "../../i18n";
import { withDomain } from "../domain-navigation";

export const AD_DOMAIN_REPORTS: ReadonlySet<string> = new Set(["ad.users.v2", "ad.computers.v6", "ad.computer-logons", "ad.infrastructure", "security.events.chains"]);
const DOMAIN_SELECTORS = ["domain", "domain_id"] as const;

/** VPN source branches load independently; NPS policy tabs do not need Accounting. */
export function vpnViewBranchKey(view: string): string {
  if (["policy_denials", "policy_denials_growth", "policy_denials_events", "windows", "windows_heatmap"].includes(view)) return view;
  return view === "authorizations" || view === "failed" ? "nps" : "accounting";
}

/** Options for a parameter: declared inline or delivered in `filter_options`. */
export function paramOptions(definition: ReportDefinitionDto, key: string, live?: Record<string, ReportOption[]>): ReportOption[] {
  const param = definition.params.find((item) => item.key === key);
  if (!param) return [];
  if (param.options?.length) return param.options;
  const source = param.options_from ?? key;
  return live?.[source] ?? definition.filter_options?.[source] ?? [];
}

/** Filter-bar fields; hidden deep-link parameters stay in the URL only. */
export function filterFields(definition: ReportDefinitionDto, live?: Record<string, ReportOption[]>, view?: string): FilterField[] {
  return definition.params.filter((param) => !param.hidden && !(definition.key === "ad.gpo.v2" && view !== "changes" && param.kind === "period")).map((param): FilterField => {
    if (param.kind === "period") return { key: param.key, label: param.label, kind: "period", presets: param.presets as PeriodPreset[] | undefined };
    if (param.kind === "choice" || param.kind === "domain") {
      const options = paramOptions(definition, param.key, live);
      return { key: param.key, label: param.label, kind: "select", options: param.kind === "domain" && !param.required
        ? [{ value: "", label: t("reports.filters.all_domains") }, ...options.filter((option) => option.value !== "")] : options };
    }
    if (param.kind === "multichoice") return { key: param.key, label: param.label, kind: "multiselect", options: paramOptions(definition, param.key, live) };
    return { key: param.key, label: param.label, kind: "text" };
  });
}

/** Common primary controls; unrecognized report forms keep their first four fields. */
export function primaryFilterKeys(definition: ReportDefinitionDto): string[] {
  const visible = definition.params.filter((param) => !param.hidden);
  const primary = visible.filter((param) => param.kind === "domain" || param.kind === "period" || param.required || ["q", "view", "threshold_days"].includes(param.key));
  return (primary.length ? primary : visible.slice(0, 4)).map((param) => param.key);
}

/** Defaults use available domains; optional domains otherwise query every accessible domain. */
export function defaultValues(definition: ReportDefinitionDto): FilterValues {
  const values: FilterValues = {};
  for (const param of definition.params) {
    if (param.kind === "period") values[param.key] = { preset: String(param.default ?? "7d") as PeriodPreset };
    else if (param.kind === "domain") {
      const options = paramOptions(definition, param.key);
      // VPN requires one domain, but source ordering must not choose an archive.
      const selected = definition.key === "vpn.connections"
        ? options.find((option) => definition.default_domain_id != null && option.value === String(definition.default_domain_id))
        : options.find((option) => option.value === String(param.default)) ?? (param.required ? options[0] : undefined);
      if (selected) values[param.key] = selected.value;
    } else if (param.default !== undefined) values[param.key] = String(param.default);
  }
  return values;
}

export function valuesFromSearch(definition: ReportDefinitionDto, search: URLSearchParams): FilterValues {
  const values = defaultValues(definition);
  if (definition.key === "vpn.connections" || definition.key === "ad.gpo.v2") {
    // Legacy workspace links use domain_id; VPN's existing API uses domain.
    if (!search.has("domain") && search.has("domain_id")) values.domain = search.get("domain_id") ?? "";
    if (search.get("scope") === "all" && !search.has("domain") && !search.has("domain_id")) delete values.domain;
  }
  if (search.get("scope") === "all") values.scope = "all";
  else if (AD_DOMAIN_REPORTS.has(definition.key) && !search.has("domain") && !search.has("domain_id")
    && definition.default_domain_id != null && definition.params.some(param => param.key === "domain")) {
    values.domain = String(definition.default_domain_id);
  }
  for (const param of definition.params) {
    if (param.kind === "period") {
      const preset = search.get("period");
      if (preset) values[param.key] = { preset: preset as PeriodPreset, from: search.get("from") ?? undefined, to: search.get("to") ?? undefined };
    } else if (param.kind === "multichoice") {
      const all = search.getAll(param.key).filter(Boolean);
      if (all.length) values[param.key] = all;
    } else {
      const value = search.get(param.key);
      if (value) values[param.key] = value;
    }
  }
  // A filtered declaration may hide the selector. The explicit URL scope still applies.
  if (AD_DOMAIN_REPORTS.has(definition.key)) {
    const domain = search.get("domain");
    const domainId = search.get("domain_id");
    if (domain || domainId) {
      delete values.domain;
      delete values.domain_id;
      if (definition.key === "security.events.chains") values.domain = domain || domainId || undefined;
      else {
        if (domain) values.domain = domain;
        if (domainId) values.domain_id = domainId;
      }
    }
  }
  if (["ad.computers.v6", "ad.computer-logons"].includes(definition.key)) {
    const canonical = definition.params.some((param) => param.key === "domain" && !param.hidden);
    const domain = values.domain ?? values.domain_id;
    if (domain && canonical && (!values.domain || !values.domain_id || values.domain === values.domain_id)) {
      values.domain = domain;
      delete values.domain_id;
    }
  }
  return values;
}

/** Filter values → URL/API parameters (the same encoding for both). */
export function searchFromValues(definition: ReportDefinitionDto, values: FilterValues, sort?: SortState | null): URLSearchParams {
  const search = new URLSearchParams();
  for (const param of definition.params) {
    const value = values[param.key];
    if (value === undefined || value === "") continue;
    if (param.kind === "period") {
      const period = value as PeriodValue;
      search.set("period", period.preset);
      if (period.preset === "custom") {
        if (period.from) search.set("from", period.from);
        if (period.to) search.set("to", period.to);
      }
    } else if (Array.isArray(value)) {
      value.forEach((item) => search.append(param.key, item));
    } else {
      search.set(param.key, String(value));
    }
  }
  if (AD_DOMAIN_REPORTS.has(definition.key)) {
    for (const key of DOMAIN_SELECTORS) {
      const selected = values[key];
      if (typeof selected === "string" && selected && !search.has(key)) search.set(key, selected);
    }
  }
  if (values.scope === "all" && !search.has("domain") && !search.has("domain_id")) search.set("scope", "all");
  if (sort) { search.set("sort", sort.field); search.set("direction", sort.direction); }
  return search;
}

export function apiParams(definition: ReportDefinitionDto, values: FilterValues, options: { sort?: SortState | null; timeZone: string; cursor?: string | null; limit?: number; view?: string }): URLSearchParams {
  const params = searchFromValues(definition, values, options.sort);
  // All is navigation-only except on single-domain VPN: retain it so even a
  // direct API call cannot reinterpret All as the recommended domain.
  if (definition.key !== "vpn.connections") params.delete("scope");
  // GPO accepts only the authorized server scope; keep navigation scope in the URL.
  if (definition.key === "ad.gpo.v2") {
    params.delete("domain");
    params.delete("domain_id");
  }
  if (definition.key === "security.events.chains" && options.view === "events") {
    for (const key of ["caller", "failure_code", "min_repeats", "failure_window", "persistence_type", "persistence_path", "persistence_change", "persistence_rarity", "activity_type", "minimum_delay", "revocation_window", "identity_scope"]) params.delete(key);
  }
  if (definition.key === "ad.computers.v6" || definition.key === "ad.gpo.v2" && options.view !== "changes") {
    for (const key of ["period", "from", "to"]) params.delete(key);
  }
  params.set("tz", options.timeZone);
  params.set("limit", String(options.limit ?? definition.limits.default));
  if (options.cursor) params.set("cursor", options.cursor);
  return params;
}

/** A custom period without both dates in order, or a missing required value, cannot be queried yet. */
export function valuesReady(definition: ReportDefinitionDto, values: FilterValues, view?: string): boolean {
  if (definition.key === "security.events.chains" && ["persistence-changes", "account-revocation", "lockout-recurring", "chains"].includes(view ?? "") && !values.domain) return false;
  return definition.params.every((param) => {
    if (param.kind === "period" && (definition.key === "ad.computers.v6" || definition.key === "ad.gpo.v2" && view !== "changes")) return true;
    const value = values[param.key];
    if (param.kind === "period") {
      const period = value as PeriodValue | undefined;
      return Boolean(period && (period.preset !== "custom" || (period.from && period.to && period.from <= period.to)));
    }
    return !param.required || (value !== undefined && value !== "");
  });
}

/** Address of a report opened with a metric filter (the same parameters the report keeps in its URL). */
export function reportHref(reportKey: string, filter?: Record<string, string>): string {
  const search = new URLSearchParams(Object.entries(filter ?? {}).filter(([, value]) => value !== ""));
  const query = search.toString();
  const href = `/app/report/${encodeURIComponent(reportKey)}${query ? `?${query}` : ""}`;
  return typeof window === "undefined" ? href : withDomain(href, window.location.search);
}

/** A preset changes only its declared parameters. */
export function applyPreset(_definition: ReportDefinitionDto, current: FilterValues, preset: Record<string, string>): FilterValues {
  return { ...current, ...preset };
}

export function isPresetActive(_definition: ReportDefinitionDto, current: FilterValues, preset: Record<string, string>): boolean {
  return Object.entries(preset).every(([key, expected]) => {
    const actual = current[key];
    return expected === (typeof actual === "string" ? actual : "");
  });
}

/**
 * Quick-scenario chips that are not already offered by a clickable metric.
 * A chip whose filter equals a metric's filter is the same action twice (plus
 * the filter field) — the metric already shows the count, so the chip is hidden.
 */
export function visiblePresets(
  definition: ReportDefinitionDto,
  _current: FilterValues,
  metricFilters: Record<string, string>[],
): ReportDefinitionDto["presets"] {
  return definition.presets.filter((preset) => !metricFilters.some(
    (filter) => Object.keys(filter).length === Object.keys(preset.params).length
      && isPresetActive(definition, filter, preset.params),
  ));
}

/** Reads `a.b.c` from a row. */
export function readPath(row: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((value, key) => (value && typeof value === "object" ? (value as Record<string, unknown>)[key] : undefined), row);
}

/** A coded value rendered through the column's labels. */
export function columnValue(column: ReportColumnDto, row: unknown): unknown {
  const value = readPath(row, column.path);
  if (column.labels && (typeof value === "string" || typeof value === "boolean")) return column.labels[String(value)] ?? (column.kind === "state" ? reportEnumText(value) : value);
  if (column.kind === "state") return reportEnumText(value);
  return value;
}

/** Fills `{path}` placeholders; returns null when a value is missing (no half-built links). */
export function fillTemplate(template: string, row: unknown): string | null {
  let missing = false;
  const href = template.replace(/\{([\w.]+)\}/g, (_, path: string) => {
    const value = readPath(row, path);
    if (value === undefined || value === null || value === "") { missing = true; return ""; }
    return encodeURIComponent(String(value));
  });
  return missing ? null : href;
}
