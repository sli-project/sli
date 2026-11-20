import { describe, expect, it } from "vitest";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { legacySecurityEventsHref, withReturnTo } from "./legacy";
import { formatCell } from "../../design-system";
import {
  apiParams, applyPreset, columnValue, defaultValues, fillTemplate, filterFields, isPresetActive,
  searchFromValues, valuesFromSearch, valuesReady, visiblePresets, vpnViewBranchKey, reportHref,
} from "./state";

it("builds scoped report links from the global domain", () => {
  const original = globalThis.window;
  Object.defineProperty(globalThis, "window", { configurable: true, value: { location: { search: "?domain=8" } } });
  try {
    expect(reportHref("ad.computers.v6", { view: "all" })).toBe("/app/report/ad.computers.v6?view=all&domain=8");
  } finally {
    if (original === undefined) Reflect.deleteProperty(globalThis, "window");
    else Object.defineProperty(globalThis, "window", { configurable: true, value: original });
  }
});

it("translates known state values while preserving text fields and declared labels", () => {
  const column = { key: "state", label: "State", kind: "state", path: "state" } as const;
  expect(columnValue(column, { state: "passed" })).toBe("Пройдено");
  expect(columnValue(column, { state: "unknown" })).toBe("Неизвестно");
  expect(columnValue(column, { state: "inactive" })).toBe("Неактивно");
  expect(columnValue({ ...column, kind: "text" }, { state: "unknown" })).toBe("unknown");
  expect(columnValue({ ...column, labels: { inactive: "Учётная запись неактивна" } }, { state: "inactive" })).toBe("Учётная запись неактивна");
  expect(columnValue({ ...column, labels: { inactive: "Учётная запись неактивна" } }, { state: "unknown" })).toBe("Неизвестно");
});

it("renders booleans as words, including state columns and their explicit labels", () => {
  const column = { key: "suppressed", label: "Suppressed", kind: "state", path: "suppressed", labels: { true: "Подавлена", false: "Не подавлена" } } as const;
  expect(columnValue(column, { suppressed: false })).toBe("Не подавлена");
  expect(columnValue(column, { suppressed: true })).toBe("Подавлена");
  expect(formatCell(false)).toBe("Нет");
  expect(formatCell(true)).toBe("Да");
});

it.each([
  ["policy_denials", "policy_denials"], ["policy_denials_growth", "policy_denials_growth"],
  ["policy_denials_events", "policy_denials_events"], ["authorizations", "nps"],
  ["failed", "nps"], ["windows", "windows"], ["windows_heatmap", "windows_heatmap"], ["employees", "accounting"],
])("selects the independent source for VPN tab %s", (view, branch) => {
  expect(vpnViewBranchKey(view)).toBe(branch);
});

const definition: ReportDefinitionDto = {
  key: "security.events.chains", section: "investigation", title: "Действия безопасности", description: "", archetype: "investigation-evidence",
  params: [
    { key: "domain", label: "Домен", kind: "domain", options_from: "domain", required: true },
    { key: "period", label: "Период", kind: "period", default: "7d", required: true, presets: ["24h", "7d", "30d", "custom"], max_days: 31 },
    { key: "category", label: "Категория", kind: "choice", options: [{ value: "account_lock", label: "Блокировка" }] },
    { key: "q", label: "Поиск", kind: "text" },
    { key: "event_db_id", label: "Событие", kind: "int", hidden: true },
  ],
  columns: [
    { key: "family", label: "Категория", kind: "state", path: "event_family", labels: { account_lock: "Блокировка" } },
    { key: "actor", label: "Кто", kind: "text", path: "actor.name" },
  ],
  views: [{ kind: "table", key: "table" }], row_key: "event_db_id", detail: "fields", export: true,
  limits: { default: 100, max: 500 },
  presets: [{ label: "Блокировки", params: { category: "account_lock" } }],
  row_links: [{ label: "Карточка", href: "/app/events/{event_db_id}" }],
  filter_options: { domain: [{ value: "1", label: "example.test" }, { value: "2", label: "other.test" }] },
};

it("uses the declared domain default only when the API includes it in available options", () => {
  const declared = { ...definition, params: definition.params.map((param) => param.kind === "domain" ? { ...param, default: "2" } : param) };
  expect(defaultValues(declared).domain).toBe("2");
  expect(valuesFromSearch(declared, new URLSearchParams("domain=1")).domain).toBe("1");
  expect(defaultValues({ ...declared, filter_options: { domain: [{ value: "7", label: "new.example.test" }] } }).domain).toBe("7");
  expect(defaultValues({ ...declared, filter_options: { domain: [] } }).domain).toBeUndefined();
});

it("keeps an optional domain unselected when its declared default is unavailable", () => {
  const optional = { ...definition, params: definition.params.map((param) => param.kind === "domain" ? { ...param, required: false, default: "99" } : param) };
  expect(defaultValues(optional).domain).toBeUndefined();
  expect(apiParams(optional, defaultValues(optional), { timeZone: "UTC" }).has("domain")).toBe(false);
  expect(valuesFromSearch(optional, new URLSearchParams("domain=2")).domain).toBe("2");
});

it("shows a period filter only for GPO changes, preserving the selected period across tabs", () => {
  const gpo = { ...definition, key: "ad.gpo.v2" };
  for (const view of ["gpos", "settings", "filtering", "delegation", "quality", "linked_scopes"]) {
    expect(filterFields(gpo, undefined, view).some((field) => field.kind === "period")).toBe(false);
  }
  expect(filterFields(gpo, undefined, "changes").some((field) => field.kind === "period")).toBe(true);
  const values = valuesFromSearch(gpo, new URLSearchParams("period=custom&from=2026-10-01&to=2026-10-07"));
  expect(searchFromValues(gpo, values).get("from")).toBe("2026-10-01");
  const incomplete = { ...values, period: { preset: "custom" as const, from: "2026-10-01" } };
  expect(valuesReady(gpo, incomplete, "gpos")).toBe(true);
  expect(valuesReady(gpo, incomplete, "changes")).toBe(false);
  expect(apiParams(gpo, incomplete, { timeZone: "UTC", view: "gpos" }).has("period")).toBe(false);
  expect(apiParams(gpo, values, { timeZone: "UTC", view: "changes" }).get("from")).toBe("2026-10-01");
});

describe("report v2 state", () => {
  it("keeps an optional domain unselected so the server queries every accessible domain", () => {
    const optional = { ...definition, params: definition.params.map((param) => param.kind === "domain" ? { ...param, required: false } : param) };
    const values = valuesFromSearch(optional, new URLSearchParams());
    expect(values.domain).toBeUndefined();
    expect(valuesReady(optional, values)).toBe(true);
    expect(apiParams(optional, values, { timeZone: "UTC" }).has("domain")).toBe(false);
    expect(filterFields(optional)[0]).toMatchObject({ options: [{ value: "", label: "Все доступные домены" }, ...definition.filter_options!.domain] });
    expect(valuesFromSearch(optional, new URLSearchParams("domain=2")).domain).toBe("2");
  });

  it("honors a declared domain default before the first domain option", () => {
    const declared = { ...definition, params: definition.params.map((param) => param.kind === "domain" ? { ...param, default: "2" } : param) };
    expect(defaultValues(declared).domain).toBe("2");
  });

  it("requires a domain only for domain-specific security views", () => {
    const optional = { ...definition, params: definition.params.map((param) => param.kind === "domain" ? { ...param, required: false } : param) };
    const values = defaultValues(optional);
    for (const view of ["table", "daily"]) expect(valuesReady(optional, values, view)).toBe(true);
    for (const view of ["chains", "persistence-changes", "account-revocation", "lockout-recurring"]) {
      expect(valuesReady(optional, values, view)).toBe(false);
      expect(valuesReady(optional, { ...values, domain: "2" }, view)).toBe(true);
    }
  });

  it("defaults to the declared period and the first domain", () => {
    expect(defaultValues(definition)).toEqual({ domain: "1", period: { preset: "7d" } });
  });

  it("round-trips filters through the URL, including hidden deep-link params", () => {
    const values = valuesFromSearch(definition, new URLSearchParams("domain=2&period=custom&from=2026-09-10&to=2026-09-12&category=account_lock&event_db_id=77"));
    expect(values).toEqual({ domain: "2", period: { preset: "custom", from: "2026-09-10", to: "2026-09-12" }, category: "account_lock", event_db_id: "77" });
    expect(searchFromValues(definition, values).toString()).toBe("domain=2&period=custom&from=2026-09-10&to=2026-09-12&category=account_lock&event_db_id=77");
  });

  it("does not show hidden params in the filter bar and takes domain options from the server", () => {
    const fields = filterFields(definition);
    expect(fields.map((field) => field.key)).toEqual(["domain", "period", "category", "q"]);
    expect(fields[0]).toMatchObject({ kind: "select", options: [{ value: "1", label: "example.test" }, { value: "2", label: "other.test" }] });
  });

  it("adds time zone and limit to API parameters", () => {
    const params = apiParams(definition, { domain: "1", period: { preset: "24h" } }, { timeZone: "Asia/Novosibirsk", cursor: "abc" });
    expect(Object.fromEntries(params)).toEqual({ domain: "1", period: "24h", tz: "Asia/Novosibirsk", limit: "100", cursor: "abc" });
  });

  it("is not ready until a custom period has both dates in order and required values are set", () => {
    expect(valuesReady(definition, { domain: "1", period: { preset: "custom", from: "2026-09-10" } })).toBe(false);
    expect(valuesReady(definition, { domain: "1", period: { preset: "custom", from: "2026-09-12", to: "2026-09-10" } })).toBe(false);
    expect(valuesReady(definition, { period: { preset: "7d" } })).toBe(false);
    expect(valuesReady(definition, { domain: "1", period: { preset: "7d" } })).toBe(true);
  });

  it("changes only preset parameters and keeps search, thresholds and hidden filters", () => {
    const current = { domain: "2", period: { preset: "30d" as const }, q: "synthetic", threshold_days: "90", event_db_id: "77", category: "other" };
    const next = applyPreset(definition, current, { category: "account_lock" });
    expect(next).toEqual({ ...current, category: "account_lock" });
    expect(current.category).toBe("other");
    expect(isPresetActive(definition, next, { category: "account_lock" })).toBe(true);
    expect(isPresetActive(definition, { ...next, q: "x" }, { category: "account_lock" })).toBe(true);
    expect(isPresetActive(definition, current, { category: "account_lock" })).toBe(false);
    expect(applyPreset(definition, next, { category: "" })).toEqual({ ...current, category: "" });
  });

  it("hides a quick-scenario chip that repeats a clickable metric", () => {
    const values = { domain: "1", period: { preset: "7d" as const } };
    expect(visiblePresets(definition, values, [])).toHaveLength(1);
    expect(visiblePresets(definition, values, [{ category: "account_lock" }])).toEqual([]);
    expect(visiblePresets(definition, values, [{ q: "other" }])).toHaveLength(1);
    expect(visiblePresets(definition, { ...values, category: "account_lock" }, [{ q: "other" }])).toHaveLength(1);
    expect(visiblePresets(definition, values, [{ category: "account_lock", q: "other" }])).toHaveLength(1);
  });

  it("reads nested paths, maps coded values to labels and never builds half links", () => {
    const row = { event_family: "account_lock", actor: { state: "observed", name: "DC1$" }, event_db_id: 5 };
    expect(columnValue(definition.columns[0], row)).toBe("Блокировка");
    expect(columnValue(definition.columns[1], row)).toBe("DC1$");
    expect(columnValue(definition.columns[1], { actor: { state: "unknown" } })).toBeUndefined();
    expect(fillTemplate("/app/events/{event_db_id}", row)).toBe("/app/events/5");
    expect(fillTemplate("/app/entities/{affected_account.entity_id}", row)).toBeNull();
  });
});

describe("legacy security events links", () => {
  it("translate old deep links keeping the exact evidence window", () => {
    const href = legacySecurityEventsHref("?domain_id=7&time_from=2026-09-10T17%3A00%3A00.123456Z&time_to=2026-09-11T17%3A00%3A00Z&timezone=Asia%2FNovosibirsk&category=account_lock&event_db_id=517550&tab=chains");
    const url = new URL(href, "http://corp.example.test");
    expect(url.pathname).toBe("/app/report/security.events.chains");
    expect(Object.fromEntries(url.searchParams)).toEqual({ domain: "7", period: "custom", from: "2026-09-10T17:00:00.123456Z", to: "2026-09-11T17:00:00Z", tz: "Asia/Novosibirsk", category: "account_lock", event_db_id: "517550", tab: "chains" });
  });

  it("translate date-only windows into calendar days", () => {
    const url = new URL(legacySecurityEventsHref("?time_from=2026-09-10&time_to=2026-09-11"), "http://corp.example.test");
    expect(url.searchParams.get("from")).toBe("2026-09-10");
    expect(url.searchParams.get("to")).toBe("2026-09-11");
  });

  it("keep a bare link valid", () => {
    expect(legacySecurityEventsHref("")).toBe("/app/report/security.events.chains");
  });

  it("carry the current report view to internal links only", () => {
    expect(withReturnTo("/app/events/5", "/app/report/security.events.chains?domain=1")).toBe("/app/events/5?return_to=%2Fapp%2Freport%2Fsecurity.events.chains%3Fdomain%3D1");
    expect(withReturnTo("https://example.test/x", "/app/report/a")).toBe("https://example.test/x");
  });
});

describe("legacy logons links", () => {
  it("map old filters to v2 parameters", async () => {
    const { legacyLogonsHref } = await import("./legacy");
    expect(legacyLogonsHref("?q=PC-1&user_q=ivanov&with_logons=true")).toBe("/app/report/ad.computer-logons?q=PC-1&user=ivanov&with_logons=yes");
    expect(legacyLogonsHref("")).toBe("/app/report/ad.computer-logons");
  });
});

describe("collection charts", () => {
  it("build one series per declared path and keep missing values as gaps", async () => {
    const { chartSpecFor } = await import("./chart-spec");
    const spec = chartSpecFor({ kind: "chart", key: "daily", chart: "timeseries", x: "date", series: [{ label: "Часы", path: "hours" }, { label: "Люди", path: "people" }] },
      [{ date: "2026-09-10", hours: 5, people: 2 }, { date: "2026-09-11", hours: null, people: 3 }]);
    expect(spec).toEqual({ kind: "timeseries", stacked: undefined, series: [
      { name: "Часы", points: [{ x: "2026-09-10", y: 5 }, { x: "2026-09-11", y: null }] },
      { name: "Люди", points: [{ x: "2026-09-10", y: 2 }, { x: "2026-09-11", y: 3 }] },
    ] });
  });

  it("build a heatmap grid in server row order and skip empty cells", async () => {
    const { chartSpecFor } = await import("./chart-spec");
    const spec = chartSpecFor({ kind: "chart", key: "heat", chart: "heatmap", x: "hour", y: "weekday", series: [{ label: "Отказов", path: "failures" }] },
      [{ hour: "00", weekday: "Пн", failures: 0 }, { hour: "01", weekday: "Пн", failures: 3 }, { hour: "00", weekday: "Вт", failures: 1 }, { hour: "01", weekday: "Вт", failures: 0 }]);
    expect(spec).toEqual({ kind: "heatmap", data: {
      xLabels: ["00", "01"], yLabels: ["Пн", "Вт"],
      cells: [{ x: 1, y: 0, value: 3 }, { x: 0, y: 1, value: 1 }],
    } });
  });
});

it("translates the declared missing-collection state without changing source text", () => {
  const column = { key: "state", label: "State", kind: "state", path: "state" } as const;
  expect(columnValue(column, { state: "not_collected" })).toBe("Данные не собраны");
  expect(columnValue({ ...column, kind: "text" }, { state: "not_collected" })).toBe("not_collected");
});
