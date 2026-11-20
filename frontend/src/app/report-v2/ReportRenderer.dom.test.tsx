// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportIntentDto, ReportResultDto } from "../../api/report-v2-types";
import { ReportRenderer } from "./ReportRenderer";
import { api } from "../../api/client";
import { OverlayProvider } from "../../design-system";
import { PAGE_ACTIONS } from "./custom";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";
import * as appContext from "../App";
import reportDefinitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import adDefinitions from "../../../../server-dotnet/src/Sli.Server/Ad/report-definitions.json";

const definition: ReportDefinitionDto = {
  key: "demo.events", section: "investigation", title: "Демо-события", description: "Проверка рендерера", archetype: "investigation-evidence",
  params: [
    { key: "domain", label: "Домен", kind: "domain", options_from: "domain", required: true },
    { key: "period", label: "Период", kind: "period", default: "7d", required: true, presets: ["24h", "7d", "custom"] },
    { key: "category", label: "Категория", kind: "choice", options: [{ value: "lock", label: "Блокировка" }] },
  ],
  columns: [
    { key: "time", label: "Время", kind: "datetime", path: "time" },
    { key: "who", label: "Кто", kind: "text", path: "actor.name" },
    { key: "family", label: "Категория", kind: "state", path: "family", labels: { lock: "Блокировка" } },
  ],
  views: [{ kind: "table", key: "table" }], row_key: "id", detail: "fields", export: true, limits: { default: 100, max: 500 },
  presets: [{ label: "Только блокировки", params: { category: "lock" } }],
  row_links: [{ label: "Карточка события", href: "/app/events/{id}" }],
  filter_options: { domain: [{ value: "1", label: "example.test" }] },
};

const page = (overrides: Partial<ReportResultDto> = {}): ReportResultDto => ({
  contract_id: "sli.report-result.v2", report_key: "demo.events", state: "ok",
  items: [{ id: 5, time: "2026-09-15T03:26:12Z", actor: { state: "observed", name: "DC1$" }, family: "lock" }],
  has_more: false, next_cursor: null, filtered_count: null, metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
  ...overrides,
});

let dataResponse: { status: number; body: unknown } = { status: 200, body: page() };
const requested: string[] = [];
const originalPrintSheet = PAGE_ACTIONS["vpn.print-sheet"];

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  requested.length = 0;
  dataResponse = { status: 200, body: page() };
  window.history.replaceState(null, "", "/app/report/demo.events");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    const payload = url.includes("/data?") ? dataResponse : { status: 200, body: definition };
    return new Response(JSON.stringify(payload.body), { status: payload.status, headers: { "Content-Type": "application/json" } });
  }));
});
afterEach(() => { cleanup(); PAGE_ACTIONS["vpn.print-sheet"] = originalPrintSheet; setLocale("ru"); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });

function renderReport(reportKey = "demo.events") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ReportRenderer reportKey={reportKey}/></QueryClientProvider>);
}

it.each(["list", "drawer"] as const)("resolves a problem from the %s in two actions", async (surface) => {
  const raw = { ...definition, ...reportDefinitions.find((item) => item.key === "security.problems"), detail: "fields" } as ReportDefinitionDto;
  const problem = { id: 7, title_text: "Synthetic problem", status: "confirmed", allowed_statuses: ["confirmed", "active", "closed"] };
  dataResponse.body = page({ report_key: raw.key, items: [problem] });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => Response.json(String(input).includes("/data?") ? dataResponse.body : raw)));
  vi.spyOn(appContext, "useEffectiveAccess").mockReturnValue({ capabilities: ["investigations.manage"] } as ReturnType<typeof appContext.useEffectiveAccess>);
  const update = vi.spyOn(api, "updateFinding").mockImplementation(async () => {
    dataResponse.body = page({ report_key: raw.key, state: "empty", items: [] });
    return { status: "ok", changed: true, finding: { ...problem, status: "closed" } } as Awaited<ReturnType<typeof api.updateFinding>>;
  });
  const client = new QueryClient();
  render(<QueryClientProvider client={client}><OverlayProvider><ReportRenderer reportKey={raw.key}/></OverlayProvider></QueryClientProvider>);

  const table = await screen.findByRole("table");
  expect(within(table).getByText("Открыта")).toBeTruthy();
  let target = table;
  if (surface === "drawer") {
    fireEvent.click(within(table).getByText(problem.title_text));
    target = screen.getByRole("dialog", { name: problem.title_text });
  }
  fireEvent.click(within(target).getByRole("button", { name: "Решено" }));
  if (surface === "list") expect(screen.queryByRole("dialog", { name: problem.title_text })).toBeNull();
  const confirm = screen.getByRole("dialog", { name: "Закрыть проблему" });
  const note = within(confirm).getByRole("textbox", { name: "Комментарий (необязательно)" });
  if (surface === "drawer") fireEvent.change(note, { target: { value: " Исправлено " } });
  expect(update).not.toHaveBeenCalled();
  fireEvent.click(within(confirm).getByRole("button", { name: "Решено" }));
  await waitFor(() => expect(update).toHaveBeenCalledExactlyOnceWith(7, { status: "closed", note: surface === "drawer" ? "Исправлено" : null }));
  await waitFor(() => expect(screen.queryByText(problem.title_text)).toBeNull());
});

it.each(["ru", "en"] as const)("renders the AD infrastructure list without data-state clutter (%s)", async (locale) => {
  setLocale(locale);
  const raw = { ...definition, ...adDefinitions["ad.infrastructure"].declaration } as unknown as ReportDefinitionDto;
  const body = page({ report_key: raw.key, state: "partial", coverage: { completeness: "not_proven" },
    items: [
      { id: 1, label: "Synthetic missing check", entity_name: "dc01.example.test", entity_type: "domain_controller", actual_value: "not_collected", actual_text: "Данные не собраны", qualification: "not_evaluated" },
      { id: 2, label: "Synthetic successful check", actual_value: 0, actual_text: "0", qualification: "passed", basis: "Synthetic methodological caveat" },
      { id: 3, label: "Synthetic value only", actual_value: false, actual_text: "Нет", qualification: "policy_not_defined" },
      { id: 4, label: "Synthetic result only", actual_value: null, actual_text: null, qualification: "failed" },
    ], metrics: [
      { key: "failed", label: "Synthetic zero metric", value: 0 },
      { key: "not_evaluated", label: "Synthetic unknown metric", value: 9 },
      { key: "passed", label: "Synthetic passed metric", value: 5 },
    ], limitations: [{ code: "synthetic", text: "Synthetic limitation" }],
  });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? body : raw,
  ), { headers: { "Content-Type": "application/json" } })));
  const { container } = renderReport(raw.key);
  const table = await screen.findByRole("table");
  expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent?.replace(/[↕↑↓]/g, ""))).toEqual(locale === "ru"
    ? ["Параметр", "Объект", "Фактическое значение", "Ожидаемое условие", "Результат", "Наблюдалось"]
    : ["Parameter", "Object", "Observed value", "Expected condition", "Result", "Observed"]);
  expect(within(table).queryByText("Synthetic missing check")).toBeNull();
  expect(table.querySelector("details")).toBeNull();
  expect(within(table).getByText("Synthetic value only")).toBeTruthy();
  expect(within(table).getByText("Synthetic result only")).toBeTruthy();
  expect(screen.queryByText("Synthetic methodological caveat")).toBeNull();
  expect(screen.queryByText(t("reports.passport.more"))).toBeNull();
  expect(window.location.search).not.toContain("spn_collisions_only");
  expect(within(table).getByText("Synthetic successful check").closest("tr")!.querySelectorAll("td")[2].textContent).toBe("0");
  expect(container.querySelector('.sli-ds-metrics')).toBeNull();
  for (const text of ["Synthetic zero metric", "Synthetic unknown metric", "Synthetic passed metric", "Данные не собраны", "Не оценено", "Synthetic limitation", t("reports.passport.more")]) expect(screen.queryByText(text)).toBeNull();
  expect(screen.queryByRole("group", { name: t("reports.renderer.quick_scenarios") })).toBeNull();
  const additional = screen.getByText(t("reports.filters.more")).closest("details")!;
  expect(additional.open).toBe(false);
  expect(additional.contains(screen.getByLabelText(locale === "ru" ? "Раздел" : "Section"))).toBe(true);
  fireEvent.click(screen.getByText(t("table.columns")));
  fireEvent.click(screen.getByRole("checkbox", { name: locale === "ru" ? "Тип объекта" : "Object type" }));
  expect(within(table).getByRole("columnheader", { name: locale === "ru" ? /Тип объекта/ : /Object type/ })).toBeTruthy();
  fireEvent.click(within(table).getByText("Synthetic successful check"));
  const drawer = screen.getByRole("dialog");
  expect(within(drawer).queryByText("Данные не собраны")).toBeNull();
  expect(within(drawer).queryByText(locale === "ru" ? "Не оценено" : "Not assessed")).toBeNull();
});

it.each(["ru", "en"] as const)("keeps both change collections in one infrastructure tab (%s)", async (locale) => {
  setLocale(locale);
  const raw = { ...definition, ...adDefinitions["ad.infrastructure"].declaration } as unknown as ReportDefinitionDto;
  window.history.replaceState(null, "", "/app/report/ad.infrastructure?tab=privileged_changes&spn_collisions_only=false");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input); requested.push(url);
    return new Response(JSON.stringify(url.includes("/data?") ? page({ report_key: raw.key,
      collections: { privileged_changes: [{ entity_id: 1, group_id: 2, kind: "added" }],
        changes: [{ object_id: "synthetic-object", object_type: "user", attribute: "displayName" }] },
    }) : raw), { headers: { "Content-Type": "application/json" } });
  }));
  renderReport(raw.key);
  await screen.findByRole("table");
  const changesTitle = locale === "ru" ? "Изменения AD" : "AD changes";
  const membershipTitle = locale === "ru" ? "Изменения привилегированного членства" : "Privileged membership changes";
  expect(screen.queryByRole("tab", { name: membershipTitle })).toBeNull();
  expect(screen.getByRole("tab", { name: changesTitle }).getAttribute("aria-selected")).toBe("true");
  expect(screen.getByRole("table").textContent).toContain(locale === "ru" ? "Добавление" : "Addition");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: changesTitle }), "changes");
  await waitFor(() => expect(requested.some((url) => url.includes("tab=changes"))).toBe(true));
  expect((await screen.findByRole("table")).textContent).toContain("synthetic-object");
  expect(window.location.search).toContain("spn_collisions_only=false");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: changesTitle }), "privileged_changes");
  await waitFor(() => expect(screen.getByRole("table").textContent).toContain(locale === "ru" ? "Добавление" : "Addition"));
});

it.each(["ok", "partial", "stale", "processing"] as const)("shows domain events as a list without data-state blocks (%s)", async (state) => {
  const raw = { ...reportDefinitions.find((item) => item.key === "security.events.chains"),
    default_domain_id: 7, default_domain_state: "available", filter_options: { domain: [{ value: "7", label: "example.test" }] },
  } as unknown as ReportDefinitionDto;
  window.history.replaceState(null, "", "/app/report/security.events.chains?tab=chains");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input); requested.push(url);
    return new Response(JSON.stringify(url.includes("/data?") ? page({ report_key: raw.key, state,
      items: [{ event_db_id: 5, time_created_utc: "2026-11-13T01:00:00Z", change_text: "блокировка", actor: { name: "operator" },
        affected_account: { name: "test-user" }, group: { name: "test-group" }, source_host: { hostname: "dc01.example.test" }, outcome_code: "unknown" }],
      metrics: [{ key: "coverage", label: "Synthetic coverage", value: 1 }],
      state_details: { reason: "freshness_exceeded", source: "dc01.example.test", stale_since_utc: "2026-11-12T01:00:00Z" },
      limitations: [{ code: "observations_only", text: "Synthetic limitation" }],
    }) : raw), { headers: { "Content-Type": "application/json" } });
  }));
  renderReport(raw.key);
  const table = await screen.findByRole("table", { name: "События" });
  expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Изменения в домене");
  expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(["Время", "Что изменено", "Кто", "Над кем", "Группа", "Где", "Итог"]);
  expect(within(table).getByText("—")).toBeTruthy();
  expect(screen.queryByLabelText("Домен")).toBeNull();
  expect(screen.queryByText("Подробнее")).toBeNull();
  expect(screen.queryByText("Synthetic coverage")).toBeNull();
  expect(screen.queryByText("Synthetic limitation")).toBeNull();
  expect(screen.queryByRole("tab")).toBeNull();
  expect(document.querySelector(".sli-ds-state--banner, .sli-ds-callout, .sli-ds-header__meta p")).toBeNull();
  expect(screen.queryByText(/Молчит источник/)).toBeNull();
  const filters = screen.getByRole("form", { name: "Фильтры" });
  for (const label of ["Блокировки", "Группы", "Пароли", "Аудит", "Неудачные"]) expect(within(filters).getByRole("button", { name: label })).toBeTruthy();
  const params = new URL(requested.find((url) => url.includes("/data?"))!, "http://example.test").searchParams;
  expect(params.get("domain")).toBe("7");
  expect(params.get("limit")).toBe("50");
  for (const key of ["tab", "min_repeats", "failure_window", "revocation_window", "identity_scope"]) expect(params.has(key)).toBe(false);
  await userEvent.click(within(filters).getByRole("button", { name: "Блокировки" }));
  await waitFor(() => expect(requested.some((url) => url.includes("event_id=4740"))).toBe(true));
  expect(window.location.search).not.toContain("tab=chains");
  expect(document.querySelector(".sli-ds-filters__additional")?.hasAttribute("open")).toBe(false);
});

it.each(["ru", "en"] as const)("renders absent domain event values as an em dash (%s)", async (locale) => {
  setLocale(locale);
  const raw = { ...reportDefinitions.find((item) => item.key === "security.events.chains"),
    default_domain_id: 7, default_domain_state: "available", filter_options: { domain: [{ value: "7", label: "example.test" }] },
  } as unknown as ReportDefinitionDto;
  const body = page({ report_key: raw.key, items: [{ event_db_id: 5, time_created_utc: "2026-11-14T01:00:00Z",
    change_text: locale === "ru" ? "Неудачный вход" : "Failed sign-in", actor: { state: "unknown", name: null, sid: null },
    affected_account: { state: "unknown" }, group: null, source_host: { hostname: "" }, outcome_code: "failure" }],
  });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? body : raw,
  ), { headers: { "Content-Type": "application/json" } })));
  renderReport(raw.key);
  const table = await screen.findByRole("table");
  const cells = within(table).getAllByRole("row")[1].querySelectorAll("td");
  expect(cells[1].textContent).toBe(locale === "ru" ? "Неудачный вход" : "Failed sign-in");
  for (const index of [2, 3]) expect(cells[index].textContent).toBe("—");
  expect(within(table).queryByRole("columnheader", { name: "Кто" })).toBeNull();
  expect(within(table).queryByRole("columnheader", { name: "Группа" })).toBeNull();
  expect(within(table).queryByText("-", { exact: true })).toBeNull();
});

it.each([false, true])("shows domain event optional columns only when the page has values (%s)", async (populated) => {
  const raw = { ...reportDefinitions.find((item) => item.key === "security.events.chains"),
    default_domain_id: 7, default_domain_state: "available", filter_options: { domain: [{ value: "7", label: "example.test" }] },
  } as unknown as ReportDefinitionDto;
  const body = page({ report_key: raw.key, items: [{ event_db_id: 4, time_created_utc: "2026-11-14T02:00:00Z" }, { event_db_id: 5, time_created_utc: "2026-11-14T01:00:00Z",
    change_text: populated ? "Изменена группа" : "—", actor: { name: populated ? "fixture-user" : " " },
    group: { name: populated ? "fixture-group" : null }, outcome_code: "success" }],
  });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? body : raw,
  ), { headers: { "Content-Type": "application/json" } })));
  renderReport(raw.key);
  const table = await screen.findByRole("table");
  for (const name of ["Что изменено", "Кто", "Группа"])
    expect(Boolean(within(table).queryByRole("columnheader", { name }))).toBe(populated);
});

it.each((["ru", "en"] as const).flatMap(locale => ["http-error", "error"].map(failure => ({ locale, failure }))))("names the failed domain events request and offers retry ($locale / $failure)", async ({ locale, failure }) => {
  setLocale(locale);
  const raw = { ...reportDefinitions.find((item) => item.key === "security.events.chains"), filter_options: {} };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?")
    ? failure === "http-error" ? { error: "synthetic_failure" } : page({ state: "error", items: [] }) : raw),
    { status: String(input).includes("/data?") && failure === "http-error" ? 500 : 200, headers: { "Content-Type": "application/json" } })));
  renderReport("security.events.chains");
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain(t("reports.domain_events.load_failed"));
  expect(within(alert).getByRole("button", { name: t("state.retry") })).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByText(t("reports.domain_events.empty"))).toBeNull();
});

it.each((["ru", "en"] as const).flatMap(locale =>
  (["ok", "empty", "not_collected", "partial", "processing", "stale"] as const).map(state => ({ locale, state }))))(
  "keeps successful rowless domain history out of the error state ($locale / $state)", async ({ locale, state }) => {
    setLocale(locale);
    const raw = { ...reportDefinitions.find(item => item.key === "security.events.chains"), filter_options: {} };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
      String(input).includes("/data?") ? page({ report_key: "security.events.chains", state, items: [], filtered_count: 0 }) : raw,
    ), { headers: { "Content-Type": "application/json" } })));
    const { container } = renderReport("security.events.chains");
    expect(await screen.findByText(t("reports.domain_events.empty"))).toBeTruthy();
    expect(screen.getAllByText(t("reports.domain_events.empty"))).toHaveLength(1);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("button", { name: t("state.retry") })).toBeNull();
    expect(container.querySelector('[data-state="error"]')).toBeNull();
  },
);

it.each((["ru", "en"] as const).flatMap(locale =>
  ["security.problems", "events.journal", "ad.infrastructure", "ad.users.v2", "ad.computers.v6", "ad.gpo.v2"].flatMap(key =>
    (["empty", "not_collected"] as const).map(state => ({ locale, key, state })))))(
  "keeps empty beta reports out of the error state ($locale / $key / $state)", async ({ locale, key, state }) => {
    setLocale(locale);
    const declaration = key in adDefinitions ? adDefinitions[key as keyof typeof adDefinitions].declaration
      : reportDefinitions.find(item => item.key === key);
    const raw = { ...declaration, default_domain_id: 7, default_domain_state: "available",
      filter_options: { domain: [{ value: "7", label: "example.test" }] } } as unknown as ReportDefinitionDto;
    let dataRequested = false;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const data = String(input).includes("/data?");
      if (data) dataRequested = true;
      return new Response(JSON.stringify(data ? page({ report_key: key, state, items: [], collections: {}, filtered_count: 0 }) : raw),
        { headers: { "Content-Type": "application/json" } });
    }));
    const { container } = renderReport(key);
    await waitFor(() => {
      expect(dataRequested).toBe(true);
      expect(container.querySelector('.sli-ds-report[data-state]:not([data-state="loading"])')).toBeTruthy();
    });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(container.querySelector('[data-state="error"], [data-state="unavailable"]')).toBeNull();
    expect(screen.queryByRole("button", { name: t("state.retry") })).toBeNull();
  },
);

it.each(["ru", "en"] as const)("shows the problem queue's default columns and three labelled paragraphs (%s)", async (locale) => {
  setLocale(locale);
  const sid = "S-1-5-21-100000001-200000002-300000003-1101";
  const raw = { ...definition, ...reportDefinitions.find((item) => item.key === "security.problems"),
    description: "Synthetic queue description", params: [], presets: [], row_links: [], detail: "fields",
  } as unknown as ReportDefinitionDto;
  dataResponse.body = page({ report_key: raw.key, items: [{ id: 7, title: "Synthetic problem", title_text: "Synthetic problem",
    severity: "high", actor: sid, actor_text: null, entity_text: "fixture-object", entity_identifiers: sid,
    presentation_messages: {}, entity_messages: ["fixture-object"],
    entities: [{ display_name: "42", entity_role: "source_host" }, { display_name: sid, entity_role: "target" }], last_seen_utc: "2026-11-13T01:00:00Z",
    occurrence_count: 3, status: "new", what_happened: "Synthetic observation", why_text: "Synthetic impact", next_text: "Synthetic action",
  }], metrics: [
    { key: "open", label: t("reports.v2.security.problems.metrics.open.label"), value: 3 },
    { key: "progress", label: t("reports.v2.security.problems.metrics.progress.label"), value: 0 },
    { key: "closed", label: t("reports.v2.security.problems.metrics.closed.label"), value: 0 },
  ] });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? dataResponse.body : raw,
  ), { headers: { "Content-Type": "application/json" } })));
  renderReport(raw.key);
  await screen.findByText("Synthetic problem");
  expect(screen.queryByText(t("reports.passport.more"))).toBeNull();
  expect(screen.queryByText(raw.description)).toBeNull();
  expect(screen.queryByText(t("reports.v2.security.problems.metrics.progress.label"))).toBeNull();
  expect(screen.queryByText(t("reports.v2.security.problems.metrics.closed.label"))).toBeNull();
  expect(screen.queryByRole("region", { name: t("reports.summaryAria") })).toBeNull();
  const table = screen.getByRole("table");
  expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(locale === "ru"
    ? ["Важность", "Проблема", "Объект", "Кто", "Последнее событие", "Раз", "Состояние"]
    : ["Severity", "Problem", "Object", "Who", "Last event", "Times", "State"]);
  expect(within(table).getAllByRole("row")[1].querySelectorAll("td")[3].textContent).toBe("—");
  fireEvent.click(screen.getByText(t("table.columns")));
  for (const key of ["actor_identifier", "entity_identifiers", "identity_sources"] as const) {
    expect(screen.queryByRole("checkbox", { name: t(`reports.v2.security.problems.columns.${key}.label`) })).toBeNull();
  }
  expect(within(table).queryByText(sid)).toBeNull();
  const riskLabel = locale === "ru" ? "Отложить" : "Snooze";
  fireEvent.click(screen.getByRole("checkbox", { name: riskLabel }));
  expect(within(table).getByRole("columnheader", { name: riskLabel })).toBeTruthy();
  fireEvent.click(within(table).getByText("Synthetic problem"));
  const drawer = screen.getByRole("dialog", { name: "Synthetic problem" });
  expect(within(drawer).getAllByText(sid).length).toBeGreaterThan(0);
  const labels = locale === "ru" ? ["Что случилось", "Почему важно", "Что сделать"] : ["What happened", "Why it matters", "What to do"];
  for (const [index, text] of ["Synthetic observation", "Synthetic impact", "Synthetic action"].entries()) {
    const paragraph = within(drawer).getByText(text, { exact: false }).closest("p");
    expect(paragraph?.textContent).toContain(labels[index]);
  }
});

it.each(["ru", "en"] as const)("keeps status filters and hides a legacy default action in %s", async (locale) => {
  setLocale(locale);
  const raw = {
    ...definition, key: "security.problems", title: "Synthetic queue", description: "",
    params: [{ key: "status", label: "Status", kind: "choice", options: [{ value: "closed", label: "Closed" }] }],
    presets: [{ label: "Closed problems", params: { status: "closed" } }],
    columns: [
      { key: "title", label: "Problem", path: "title_text", kind: "text" },
      { key: "next", label: "Action", path: "next_text", kind: "text", hidden_by_default: true },
    ],
  } satisfies ReportDefinitionDto;
  const oldCode = "security.problems.presentation.default_next";
  const fetchReport = vi.fn(async (input: RequestInfo | URL) => Response.json(String(input).includes("/data?") ? page({
    report_key: raw.key,
    items: [{ id: 7, title_text: "Synthetic problem", next_text: "Legacy internal action",
      presentation_messages: { next_text: { code: oldCode, text: "Legacy internal action", params: {} } } }],
    metrics: [{ key: "closed", label: "Closed count", value: 3, filter: { status: "closed" } }],
  }) : raw));
  vi.stubGlobal("fetch", fetchReport);
  window.history.replaceState(null, "", "/app/report/security.problems");
  renderReport(raw.key);
  const table = await screen.findByRole("table");
  expect(screen.queryByText("Closed count")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Closed problems" }));
  await waitFor(() => expect(fetchReport.mock.calls.some(([url]) => String(url).includes("status=closed"))).toBe(true));
  fireEvent.click(within(table).getByText("Synthetic problem"));
  const drawer = screen.getByRole("dialog");
  expect(within(drawer).getByText(locale === "en" ? "What to do" : "Action").parentElement?.textContent).toContain("—");
  expect(within(drawer).queryByText(/Legacy internal action/)).toBeNull();
});

it.each(["partial", "stale", "processing", "not_collected"] as const)("keeps queue data states off the working table (%s)", async (state) => {
  const raw = { ...definition, key: "security.problems", params: [], presets: [] };
  dataResponse.body = page({ state, items: [{ id: 7, actor: { name: "fixture-account" } }],
    state_details: { reason: "freshness_exceeded", source_issues: [{ source: "fixture-dc", reason: "freshness_exceeded", since_utc: "2026-11-13T01:00:00Z" }] },
    metrics: [{ key: "progress", label: "Progress fixture", value: 2 }, { key: "closed", label: "Closed fixture", value: 1 }],
  });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? dataResponse.body : raw))));
  const view = renderReport(raw.key);
  await screen.findByText("fixture-account");
  expect(screen.queryByText(/fixture-dc/)).toBeNull();
  expect(view.container.querySelector(".sli-ds-state--banner")).toBeNull();
  expect(screen.queryByText("Progress fixture")).toBeNull();
  expect(screen.queryByText("Closed fixture")).toBeNull();
});

it.each(["ru", "en"] as const)("does not copy an unrelated shell collection failure into a healthy report (%s)", async (locale) => {
  setLocale(locale);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(["overview", "shell"], { agent_collection: {
    state: "error", active_agents: 1, current_agents: 0, items: [{
      id: "unrelated-agent", name: "unrelated-collector", state: "error", domains: ["other.example.test"],
    }],
  } });
  render(<QueryClientProvider client={client}><ReportRenderer reportKey="demo.events"/></QueryClientProvider>);
  await screen.findByText("DC1$");
  expect(screen.queryByText(/unrelated-collector/)).toBeNull();
  expect(screen.queryByText("unrelated-collector", { exact: false })).toBeNull();
  expect(requested.some((url) => url.includes("/overview"))).toBe(false);
});

it.each((["ru", "en"] as const).flatMap((locale) => [149, 161].map((repeats) => ({ locale, repeats }))))("loads every problem group and retains $repeats occurrence links in $locale", async ({ locale, repeats }) => {
  setLocale(locale);
  vi.spyOn(appContext, "useTimeZone").mockReturnValue({ timeZone: "UTC", setTimeZone: vi.fn() });
  const raw: ReportDefinitionDto = { ...definition, key: "security.problems", title: "Synthetic queue",
    params: [{ key: "population", label: "Population", kind: "choice", default: "open", options: [{ value: "open", label: "Open" }] },
      { key: "domain", label: "Domain", kind: "domain", hidden: true },
      { key: "cohort", label: "Cohort", kind: "text", hidden: true }],
    columns: [{ key: "title", label: "Problem", kind: "text", path: "title" },
      { key: "occurrence_count", label: t("reports.v2.security.problems.columns.occurrence_count.label"), kind: "number", path: "occurrence_count", component: "problems.occurrences" }],
    presets: [], row_links: [], detail: "none", limits: { default: 50, max: 200 },
  };
  const groups = Array.from({ length: 61 }, (_, index) => ({ id: 209 - index,
    title: `Synthetic problem ${index + 1}`, occurrence_count: index === 0 ? repeats : 1,
    problem_cohort: ["queue", "synthetic-rule", "synthetic-actor", `object-${index}`, [], "2026-10-25"],
  }));
  expect(groups.reduce((sum, group) => sum + group.occurrence_count, 0)).toBe(60 + repeats);
  window.history.replaceState(null, "", "/app/report/security.problems?domain=7&population=open&tz=UTC");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    const offset = new URL(url, window.location.origin).searchParams.get("cursor") === "next-50" ? 50 : 0;
    return new Response(JSON.stringify(url.includes("/data?") ? page({ report_key: raw.key,
      items: groups.slice(offset, offset + 50), has_more: offset === 0, next_cursor: offset === 0 ? "next-50" : null,
      filtered_count: groups.length, metrics: [{ key: "open", label: t("reports.v2.security.problems.metrics.open.label"), value: groups.length }],
    }) : raw), { headers: { "Content-Type": "application/json" } });
  }));
  renderReport(raw.key);
  await screen.findByText("Synthetic problem 1");
  expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(51);
  expect(screen.getByText(`${t("table.shown", { count: 50 })} ${t("table.of", { total: 61 })}`)).toBeTruthy();
  const repeatLink = screen.getByRole("link", { name: locale === "ru" ? `${repeats} раз` : `${repeats} occurrences` });
  const href = new URL(repeatLink.getAttribute("href")!, window.location.origin);
  expect(JSON.parse(href.searchParams.get("cohort")!)).toEqual(groups[0].problem_cohort);
  expect(href.searchParams.get("domain")).toBe("7");
  expect(href.searchParams.get("population")).toBe("open");
  expect(href.searchParams.get("tz")).toBe("UTC");
  fireEvent.click(screen.getByRole("button", { name: t("table.loadMore") }));
  await screen.findByText("Synthetic problem 61");
  expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(62);
  expect(screen.getByText(`${t("table.shown", { count: 61 })} ${t("table.of", { total: 61 })}`)).toBeTruthy();
  expect(screen.queryByRole("button", { name: t("table.loadMore") })).toBeNull();
  const dataRequests = requested.filter((url) => url.includes("/data?"));
  expect(dataRequests).toHaveLength(2);
  expect(new URL(dataRequests[1], window.location.origin).searchParams.get("cursor")).toBe("next-50");
});

it("opens RANSOM reasons alongside the retained file evidence in both languages", async () => {
  const raw: ReportDefinitionDto = { ...definition, key: "file-audit.mass-operations", params: [], presets: [], row_links: [],
    columns: [{ key: "employee", label: "Synthetic actor", kind: "text", path: "employee" }],
    detail: { title: "Synthetic file evidence", key: "id", kind: "inline", inline: "evidence", row_links: [],
      columns: [{ key: "path", label: "Synthetic file", kind: "text", path: "path" }] } };
  const body = page({ report_key: raw.key, items: [{ id: "synthetic-result", employee: "Synthetic actor",
    details: { threshold: 100, window_seconds: 300, distinct_files: 110 },
    ransom: { state: "excluded", exclusion: { reason: "Synthetic backup approval", approved_by: "synthetic-admin",
      active_from: "2026-10-18T00:00:00Z", active_to: "2026-10-18T01:00:00Z" } },
    evidence: [{ path: "C:\\synthetic\\file.txt" }],
  }] });
  for (const locale of ["ru", "en"] as const) {
    setLocale(locale);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(
      JSON.stringify(String(input).includes("/data?") ? body : raw), { headers: { "Content-Type": "application/json" } },
    )));
    renderReport(raw.key);
    fireEvent.click((await screen.findAllByText("Synthetic actor")).at(-1)!);
    expect(await screen.findByRole("heading", { name: t("file-audit.ransom.title") })).toBeTruthy();
    expect(screen.getByText(t("file-audit.ransom.state.excluded"))).toBeTruthy();
    expect(screen.getByText("Synthetic backup approval")).toBeTruthy();
    expect(screen.getByText("C:\\synthetic\\file.txt")).toBeTruthy();
    cleanup();
  }
});

it.each([
  "source_timeout", "source_not_initialized", "source_access_denied", "source_unavailable",
] as const)("explains workstation %s in one status line in both languages", async (reason) => {
  const raw: ReportDefinitionDto = { ...definition, key: "workstations.processes", section: "reports/workstations",
    params: definition.params.filter((param) => param.key === "period"), presets: [], row_links: [] };
  for (const locale of ["ru", "en"] as const) {
    setLocale(locale);
    const body = page({ report_key: raw.key, state: "error", items: [], coverage: { state: "error", reason },
      state_message: { code: "reports.state.error", params: {} },
      limitations: [{ code: reason, text: ru[`reports.workstations.${reason}`] }],
    });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(
      JSON.stringify(String(input).includes("/data?") ? body : raw), { headers: { "Content-Type": "application/json" } },
    )));
    const { container } = renderReport(raw.key);
    const status = await screen.findByText(t(`reports.workstations.${reason}`));
    expect(status.tagName).toBe("P");
    expect(status.getAttribute("role")).toBe("status");
    expect(screen.getAllByRole("status")).toHaveLength(1);
    expect(container.textContent).not.toContain(t("reports.state.error"));
    expect(container.textContent).not.toContain("source_unreadable");
    expect(screen.queryByRole("table")).toBeNull();
    expect(en[`reports.workstations.${reason}`]).not.toBe(ru[`reports.workstations.${reason}`]);
    cleanup();
  }
});

it.each(["policy_denials", "policy_denials_growth", "policy_denials_events"])("keeps %s data and its requested window without a view note", async (tab) => {
  const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [], views: [
    { kind: "table", key: tab, source: tab, title: "Synthetic NPS", note: "Synthetic NPS note",
      columns: [{ key: "network_policy", label: "Policy", kind: "text", path: "network_policy" }] },
    { kind: "table", key: "windows", source: "windows", title: "Windows" },
  ] };
  window.history.replaceState(null, "", `/app/report/vpn.connections?domain=1&period=90d&tab=${tab}`);
  for (const locale of ["ru", "en"] as const) {
    setLocale(locale);
    const body = page({ report_key: "vpn.connections", state: "partial", items: [],
      window: { from_utc: "2026-09-12T00:00:00Z", to_utc_exclusive: "2026-10-13T00:00:00Z", nps_period_clamped: true },
      branches: { [tab]: { state: "partial", reason: "source_completeness_not_proven", limitations: [] },
        windows: { state: "not_requested", reason: "load_on_open", limitations: [] } },
      collections: { [tab]: [{ network_policy: "Synthetic policy" }] },
    });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      return new Response(JSON.stringify(url.includes("/data?") ? body : raw), { headers: { "Content-Type": "application/json" } });
    }));
    const { container } = renderReport("vpn.connections");
    await screen.findByText("Synthetic policy");
    expect(screen.queryByText(t("reports.v2.vpn.connections.nps_period_clamped"))).toBeNull();
    expect(screen.queryByText("Synthetic NPS note")).toBeNull();
    expect(screen.queryByText(t("reports.v2.vpn.connections.period_note"))).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(container.textContent).not.toContain("6272");
    const dataUrl = requested.filter((url) => url.includes("/data?")).at(-1)!;
    const params = new URL(dataUrl, window.location.origin).searchParams;
    expect(new Date(params.get("to")!).getTime() - new Date(params.get("from")!).getTime()).toBe(90 * 86400_000);
    expect(new URLSearchParams(window.location.search).get("period")).toBe("90d");
    expect(screen.getByRole("tab", { name: /Windows/ }).textContent).toContain(t("reports.renderer.branch_state.not_requested"));
    cleanup();
  }
});

it("keeps the regular NPS note for an unclamped period", async () => {
  const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", views: [
    { kind: "table", key: "policy_denials", source: "policy_denials", note: "Synthetic note",
      columns: [{ key: "network_policy", label: "Policy", kind: "text", path: "network_policy" }] },
  ] };
  window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1&period=7d&tab=policy_denials");
  const body = page({ report_key: "vpn.connections", state: "partial", items: [], window: { nps_period_clamped: false },
    collections: { policy_denials: [{ network_policy: "Synthetic policy" }] } });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? body : raw),
    { headers: { "Content-Type": "application/json" } })));
  renderReport("vpn.connections");
  await screen.findByText("Synthetic policy");
  expect(screen.queryByText(t("reports.v2.vpn.connections.nps_period_clamped"))).toBeNull();
});

it("opens the other VPN tabs with the full 90-day window", async () => {
  const keys = ["employees", "session_overlap", "daily", "departments", "entitlements", "failed", "authorizations", "windows", "windows_heatmap"];
  const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [], views: keys.map((key) => ({
    key, kind: "table", source: key, title: key, columns: [{ key: "label", label: "Label", path: "label", kind: "text" }],
  })) };
  window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1&period=90d");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    const tab = new URL(url, window.location.origin).searchParams.get("tab") ?? "employees";
    return new Response(JSON.stringify(url.includes("/data?") ? page({ report_key: "vpn.connections", items: [],
      collections: { [tab]: [{ label: `Synthetic ${tab}` }] } }) : raw), { headers: { "Content-Type": "application/json" } });
  }));
  renderReport("vpn.connections");
  await screen.findByText("Synthetic employees");
  const tabs = screen.getAllByRole("tab");
  for (const [index, key] of keys.entries()) {
    await userEvent.click(tabs[index]);
    await screen.findByText(`Synthetic ${key}`);
    expect(new URLSearchParams(window.location.search).get("period")).toBe("90d");
    expect(screen.queryByText(t("reports.v2.vpn.connections.nps_period_clamped"))).toBeNull();
  }
  const requests = requested.filter((url) => url.includes("/data?")).map((url) => new URL(url, window.location.origin).searchParams);
  expect(requests).toHaveLength(keys.length);
  for (const params of requests) {
    expect([params.get("from"), params.get("to")]).toEqual([requests[0].get("from"), requests[0].get("to")]);
    expect(new Date(params.get("to")!).getTime() - new Date(params.get("from")!).getTime()).toBe(90 * 86400_000);
  }
});

it("selects the server-declared registered domain instead of the first domain", async () => {
  const configured: ReportDefinitionDto = {
    ...definition,
    params: definition.params.map((param) => param.kind === "domain" ? { ...param, default: "17" } : param),
    filter_options: { domain: [{ value: "11", label: "first.example.test" }, { value: "17", label: "second.example.test" }] },
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    return new Response(JSON.stringify(url.includes("/data?") ? page() : configured), { headers: { "Content-Type": "application/json" } });
  }));
  renderReport();
  await screen.findByRole("table", { name: "Демо-события" });
  expect((screen.getByLabelText("Домен") as HTMLSelectElement).value).toBe("17");
  const dataUrl = requested.find((url) => url.includes("/data?"))!;
  expect(new URL(dataUrl, window.location.origin).searchParams.get("domain")).toBe("17");
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("17");
});

it.each(["ru", "en"] as const)("requests all accessible security domains and categories by default (%s)", async (locale) => {
  setLocale(locale);
  const raw: ReportDefinitionDto = { ...definition, key: "security.events.chains", params: definition.params.map((param) =>
    param.kind === "domain" ? { ...param, required: false } : param), filter_options: { domain: [
    { value: "1", label: "Synthetic old domain" }, { value: "8", label: "Synthetic current domain" },
  ] } };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    return new Response(JSON.stringify(url.includes("/data?") ? page({ report_key: raw.key }) : raw),
      { headers: { "Content-Type": "application/json" } });
  }));
  renderReport(raw.key);
  await waitFor(() => expect(requested.some((url) => url.includes("/data?"))).toBe(true));
  const query = new URL(requested.find((url) => url.includes("/data?"))!, "http://example.test").searchParams;
  expect(query.has("domain")).toBe(false);
  expect(query.has("category")).toBe(false);
  expect(query.get("period")).toBe("7d");
  expect(screen.getByRole("option", { name: t("reports.filters.all_domains") }).closest("select")?.value).toBe("");
});

it.each(["ru", "en"] as const)("dispatches file audit to its eight-tab report body (%s)", async (locale) => {
  setLocale(locale);
  const raw: ReportDefinitionDto = { ...definition, key: "file-audit.actions", params: [
    { key: "period", label: "Период", kind: "period", default: "24h", required: true },
  ] };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? page({ report_key: raw.key, filtered_count: 1 }) : raw,
  ), { headers: { "Content-Type": "application/json" } })));
  renderReport(raw.key);
  await screen.findByRole("heading", { name: t("file-audit.headings.actions") });
  expect(screen.getAllByRole("tab")).toHaveLength(8);
  expect(screen.getByRole("checkbox", { name: t("file-audit.include_nested") })).toBeTruthy();
  expect(screen.getByText(t("table.range", { from: 1, to: 1, total: 1 }))).toBeTruthy();
});

it.each(["ru", "en"] as const)("keeps an empty collection free of limitation notes (%s)", async (locale) => {
  setLocale(locale);
  const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [], views: [
    { kind: "table", key: "windows", source: "windows", title: "Windows", columns: [] },
  ] };
  window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1&tab=windows");
  const params = { count: 200, accounts: 10, failures: 10, sources: 5, hours: 24, maximum: 3,
    from: "2026-08-21T00:00:00Z", to: "2026-08-22T00:00:00Z", event: 201 };
  const notes = ["windows_truncated", "windows_review_whole_period", "windows_distributed_review",
    "windows_earlier_failure_context_displayed_sample_only", "windows_unknown_results_remain_unknown",
    "windows_source_completeness_not_proven"].map((code) => {
    const key = `reports.v2.vpn.connections.limitations.${code}` as keyof typeof ru;
    return { code, params, text: ru[key].replace(/\{(\w+)\}/g, (match, name: string) =>
      name in params ? String(params[name as keyof typeof params]) : match) };
  });
  const body = page({ report_key: "vpn.connections", state: "partial", items: [],
    limitations: notes, collections: { windows: [] },
    branches: { windows: { state: "partial", reason: "result_truncated", limitations: notes } },
  });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? body : raw,
  ), { headers: { "Content-Type": "application/json" } })));
  renderReport(raw.key);
  await waitFor(() => expect(document.querySelector('[data-state="empty"]')).toBeTruthy());
  expect(document.querySelectorAll(".sli-ds-state")).toHaveLength(1);
  for (const note of notes) expect(screen.queryByText(note.text, { exact: false })).toBeNull();
});

it("shows the GPO snapshot date on inventory tabs and the selected period on changes", async () => {
  const raw: ReportDefinitionDto = { ...definition, key: "ad.gpo.v2", title: "Synthetic GPO",
    params: definition.params.filter((param) => param.kind === "period"),
    views: [{ key: "gpos", kind: "table", title: "Synthetic inventory" }, { key: "changes", kind: "table", title: "Synthetic changes", source: "changes", columns: definition.columns }],
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const changes = new URL(url, "http://synthetic.test").searchParams.get("tab") === "changes";
    return new Response(JSON.stringify(url.includes("/data?") ? page({ report_key: raw.key,
      coverage: { observed_at_utc: "2026-10-07T00:00:00Z" },
      window: changes ? { from_utc: "2026-10-01T00:00:00Z", to_utc_exclusive: "2026-10-08T00:00:00Z" } : {},
      collections: changes ? { changes: [] } : {},
    }) : raw));
  }));
  renderReport(raw.key);
  await screen.findByText(/^Данные от/);
  expect(screen.queryByText(/^Период:/)).toBeNull();
  fireEvent.click(screen.getByRole("tab", { name: "Изменения" }));
  await screen.findByText(/^Период:/);
  expect(screen.queryByText(/^Данные от/)).toBeNull();
});

it("offers latest observations and a baseline change for empty partial pairs while preserving filters", async () => {
  const raw: ReportDefinitionDto = { ...definition, key: "ad.new-logon-pairs", title: "Synthetic pairs",
    params: [{ key: "period", kind: "period", label: "Период", default: "24h" },
      { key: "baseline_days", kind: "int", label: "Базовое окно, дней", default: 30 },
      { key: "user", kind: "text", label: "Пользователь", default: "synthetic-user" }],
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    return new Response(JSON.stringify(url.includes("/data?") ? page({ report_key: raw.key, state: "partial", items: [],
      coverage: { baseline_history_covered: false, period_covered: false, history_from_utc: "2026-09-10T00:00:00Z", history_to_utc: "2026-09-15T12:00:00Z" },
    }) : raw));
  }));
  renderReport(raw.key);
  const baseline = await screen.findByRole("button", { name: "Базовое окно: 1 день" });
  fireEvent.click(baseline);
  await waitFor(() => expect(requested.some((url) => url.includes("/data?") && url.includes("baseline_days=1&"))).toBe(true));
  fireEvent.click(await screen.findByRole("button", { name: "Показать день последних наблюдений" }));
  await waitFor(() => expect(new URLSearchParams(window.location.search).get("period")).toBe("custom"));
  expect(new URLSearchParams(window.location.search).get("from")).toBe("2026-09-15");
  expect(new URLSearchParams(window.location.search).get("to")).toBe("2026-09-15");
  expect(new URLSearchParams(window.location.search).get("baseline_days")).toBe("1");
  expect(new URLSearchParams(window.location.search).get("user")).toBe("synthetic-user");
});

it.each(["ru", "en"] as const)("qualifies metric values with unknown period coverage (%s)", async (locale) => {
  setLocale(locale);
  dataResponse.body = page({ state: "partial", metrics: [
    { key: "unknown", label: "Synthetic unknown", value: null, quality: "unknown" },
    { key: "observed", label: "Synthetic observed", value: 2, quality: "observed" },
    { key: "zero", label: "Synthetic zero", value: 0, quality: "complete" },
  ] });
  const { container } = renderReport();
  await screen.findByText("Synthetic unknown");
  const metrics = container.querySelector(".sli-ds-metrics")!;
  expect(metrics.textContent).toContain(locale === "ru" ? "Нет данных" : "No data");
  expect(metrics.textContent).toContain(locale === "ru" ? "Наблюдалось 2, покрытие неполное" : "Observed 2, coverage incomplete");
  expect(metrics.textContent).toContain("0");
});

it.each(["security.problems", "ad.infrastructure"])("opens the exact server-checked deep link row for %s", async (key) => {
  const parameter = key === "security.problems" ? "id" : "row_id";
  const raw: ReportDefinitionDto = { ...definition, key, row_key: parameter, params: [{ key: parameter, label: "Synthetic id", kind: "text", hidden: true }] };
  window.history.replaceState(null, "", `/app/report/${key}?${parameter}=123`);
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?")
    ? page({ report_key: key, items: [{ [parameter]: 123, actor: { name: "synthetic-object" } }] }) : raw)));
  vi.stubGlobal("fetch", fetchMock);
  renderReport(key);
  expect(await screen.findByRole("dialog")).toBeTruthy();
  expect(new URLSearchParams(window.location.search).get(parameter)).toBe("123");
  const dataUrl = fetchMock.mock.calls.map(([input]) => String(input)).find((url) => url.includes("/data?"));
  expect(new URL(dataUrl!, "http://synthetic.test").searchParams.get(parameter)).toBe("123");
});

it("does not substitute a different problem for an absent deep link id", async () => {
  const raw: ReportDefinitionDto = { ...definition, key: "security.problems", params: [{ key: "id", label: "Synthetic id", kind: "text", hidden: true }] };
  window.history.replaceState(null, "", "/app/report/security.problems?id=123");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?")
    ? page({ report_key: raw.key, items: [{ id: 456, actor: { name: "synthetic-other" } }] }) : raw))));
  renderReport(raw.key);
  await screen.findByText("synthetic-other");
  expect(screen.queryByRole("dialog")).toBeNull();
});

it.each(["ru", "en"] as const)("omits an undated source state message while retaining rows (%s)", async (locale) => {
  setLocale(locale);
  dataResponse.body = page({ state: "partial", state_message: { code: "future.state", params: {}, text: "Server state title" },
    state_details: { reason: "coverage_incomplete", missing_sources: ["fixture-source"] } });
  renderReport();
  await screen.findByText("DC1$");
  expect(screen.queryByText("Server state title")).toBeNull();
  expect(screen.queryByText("fixture-source", { exact: false })).toBeNull();
  expect(document.querySelector(".sli-ds-state")).toBeNull();
});

it.each(["ru", "en"] as const)("keeps a processing report without a state banner in %s", async (locale) => {
  setLocale(locale);
  dataResponse.body = page({ state: "processing", state_message: { code: "reports.state.processing", params: {}, text: "other locale" } });
  renderReport();
  expect(await screen.findByText("DC1$")).toBeTruthy();
  expect(screen.queryByText(t("reports.state.processing"))).toBeNull();
  expect(screen.queryByText("other locale")).toBeNull();
});

it("retains the merged workspace view while report filters rewrite the URL", async () => {
  window.history.replaceState(null, "", "/app/report/demo.events?domain=1&period=7d&nav_view=logons#evidence");
  renderReport();
  const preset = await screen.findByRole("button", { name: "Только блокировки" });
  fireEvent.click(preset);
  await waitFor(() => expect(new URLSearchParams(window.location.search).get("category")).toBe("lock"));
  expect(new URLSearchParams(window.location.search).get("nav_view")).toBe("logons");
  expect(window.location.hash).toBe("#evidence");
});

it.each(["ru", "en"] as const)("renders rule-quality passport, unknown rates, cohort drill-down and period/sort requests (%s)", async (locale) => {
  setLocale(locale);
  const messages = locale === "en" ? en : ru;
  const raw: ReportDefinitionDto = { ...definition,
    key: "security.rule-quality", title: "Качество правил", description: "", export: false, detail: "none",
    intent: { ...passport,
      question: ru["reports.v2.security.rule-quality.intent.question"],
      denominator: ru["reports.v2.security.rule-quality.intent.denominator"],
      freshness_expectation: ru["reports.v2.security.rule-quality.intent.freshness_expectation"],
      primary_archetype: "summary",
    },
    params: [{ key: "period", label: "Период", kind: "period", default: "30d", required: true,
      max_days: 90, presets: ["7d", "30d", "custom"] }],
    columns: [
      { key: "rule_code", label: "Правило", kind: "text", path: "rule_code",
        link: "/app/report/security.problems?rule_code={rule_code}&created_from={cohort_from}&created_to={cohort_to}&show_suppressed=true" },
      { key: "false_positive_rate", label: "Ложные срабатывания, %", kind: "number", path: "false_positive_rate", sortable: true },
    ], filter_options: {}, presets: [], row_links: [], row_key: "rule_code",
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    const body = url.includes("/data?") ? page({ report_key: raw.key,
      items: [{ rule_code: "semantic.synthetic", false_positive_rate: null,
        cohort_from: "2026-10-01T00:00:00Z", cohort_to: "2026-10-07T00:00:00Z" }],
      coverage: { completeness: "not_proven" },
      limitations: [{ code: "accepted_risk_unavailable", text: "Метрика принятого риска недоступна." }],
    }) : raw;
    return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
  }));
  const { container } = renderReport(raw.key);
  const link = await screen.findByRole("link", { name: "semantic.synthetic" });
  const header = container.querySelector("header")!;
  for (const field of ["freshness_expectation"] as const) {
    expect(header.textContent).toContain(messages[`reports.v2.security.rule-quality.intent.${field}`]);
  }
  expect(header.textContent).not.toMatch(/Полнота|Completeness/i);
  const url = new URL(link.getAttribute("href")!, "http://synthetic.test");
  expect(url.pathname).toBe("/app/report/security.problems");
  expect(url.searchParams.get("rule_code")).toBe("semantic.synthetic");
  expect(url.searchParams.get("created_from")).toBe("2026-10-01T00:00:00Z");
  expect(url.searchParams.get("created_to")).toBe("2026-10-07T00:00:00Z");
  expect(url.searchParams.get("show_suppressed")).toBe("true");
  expect(within(screen.getByRole("table")).getByText("—")).toBeTruthy();
  expect(screen.getByText(locale === "en" ? en["reports.v2.security.rule-quality.limitations.accepted_risk_unavailable"]
    : "Метрика принятого риска недоступна.")).toBeTruthy();
  expect(requested.some((request) => request.includes("period=30d"))).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: new RegExp(messages["reports.v2.security.rule-quality.columns.false_positive_rate.label"]) }));
  await waitFor(() => expect(requested.some((request) => request.includes("sort=false_positive_rate"))).toBe(true));
});

const passport: ReportIntentDto = {
  contract_id: "sli.report-intent.v1", version: 1, user_role: "Reviewer",
  question: ru["reports.v2.ad.computers.v6.intent.question"],
  denominator: ru["reports.v2.ad.computers.v6.intent.denominator"],
  freshness_expectation: ru["reports.v2.ad.computers.v6.intent.freshness_expectation"],
  action: "Review evidence", scope: "Granted scope", exclusions: "No inferred activity",
  sources: ["Canonical snapshot"], rights: "Server grant", field_classes: ["technical"],
  coverage: "Expected snapshot", completeness: "Source-confirmed population",
  retention: "Bounded source evidence", provenance: "Snapshot identity", primary_archetype: "list",
};

it.each(["ru", "en"] as const)("omits the computer passport and source quality from the report header (%s)", async (locale) => {
  setLocale(locale);
  const raw = { ...definition, key: "ad.computers.v6", intent: passport };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? page({ coverage: { completeness: "not_proven" } }) : raw,
  ))));
  const view = renderReport(raw.key);
  await screen.findByRole("table");
  const element = view.container.querySelector("header")!;
  const messages = locale === "en" ? en : ru;
  expect(element.textContent).not.toContain(messages["reports.v2.ad.computers.v6.intent.question"]);
  expect(element.textContent).not.toContain(messages["reports.v2.ad.computers.v6.intent.denominator"]);
  expect(element.textContent).not.toContain(messages["reports.v2.ad.computers.v6.intent.freshness_expectation"]);
  expect(element.textContent).not.toMatch(/Полнота|Completeness/i);
  expect(within(element).queryByText(t("reports.passport.more"))).toBeNull();
  expect(element.querySelector("details")).toBeNull();
});

it("keeps the description when an older server omits the passport", async () => {
  const view = renderReport();
  await screen.findByRole("table");
  expect(within(view.container.querySelector("header")!).getByText(definition.description).closest("details")?.open).toBe(false);
  expect(screen.queryByText(/Основа измерения полноты:/)).toBeNull();
});

it("shows the page title once with one description and no repeated question", async () => {
  const raw = { ...definition, intent: passport };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? page() : raw,
  ))));
  const { container } = renderReport();
  await screen.findByRole("table");
  const header = container.querySelector("header")!;
  expect(within(header).getAllByText(raw.title)).toHaveLength(1);
  expect(header.querySelectorAll("h1")).toHaveLength(1);
  expect(within(header).getByText(raw.description).closest("details")?.open).toBe(false);
  expect(header.querySelector(".sli-ds-header__subtitle")?.textContent ?? "").not.toContain(raw.description);
  expect(header.textContent).not.toContain(passport.question);
  expect(header.querySelector("details")?.open).toBe(false);
});

it.each(["ru", "en"] as const)("omits server limitation notes from a partial report (%s)", async (locale) => {
  setLocale(locale);
  dataResponse.body = page({ state: "partial", state_details: { reason: "result_truncated", source: "fixture-source", stage: "query" },
    limitations: [{ code: "synthetic-limit", text: "Synthetic query limit reached" }, { code: "synthetic-baseline", text: "Synthetic baseline missing" }] });
  const { container } = renderReport();
  await screen.findByRole("table");
  expect(container.querySelector('[data-state="partial"][role="status"]')).toBeNull();
  expect(screen.queryByText("Synthetic query limit reached", { exact: false })).toBeNull();
  expect(screen.queryByText("Synthetic baseline missing", { exact: false })).toBeNull();
});

it.each([false, true])("omits undated source warnings with operations access %s", async (allowed) => {
  vi.spyOn(appContext, "useEffectiveAccess").mockReturnValue({ capabilities: allowed ? ["operations.view"] : [] } as ReturnType<typeof appContext.useEffectiveAccess>);
  dataResponse.body = page({ state: "partial", state_details: { reason: "coverage_incomplete", source: { hostname: "fixture-source" }, stage: "collection",
    source_issues: [{ source: "fixture-source", reason: "source_failed" }] } });
  const { container } = renderReport();
  await screen.findByRole("table");
  expect(container.querySelector('[data-state="partial"][role="status"]')).toBeNull();
  expect(screen.queryByRole("link", { name: t("reports.empty.source_diagnostics") })).toBeNull();
});

it("does not transfer Accounting completeness or freshness to the NPS lane", async () => {
  window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1&tab=authorizations");
  const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", intent: passport,
    views: [{ kind: "table", key: "employees" }, { kind: "table", key: "authorizations", source: "authorizations", title: "NPS" }] };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? page({
      coverage: { completeness: "complete", observed_at_utc: "2026-10-06T12:00:00Z" },
      branches: { nps: { state: "partial", reason: "source_completeness_not_proven", limitations: [] } },
    }) : raw,
  ))));
  const view = renderReport(raw.key);
  await screen.findByRole("tab", { name: /NPS.*Неполные данные/ });
  const element = view.container.querySelector("header")!;
  expect(element.textContent).not.toMatch(/Полнота|Completeness/i);
  expect(element.textContent).not.toContain(t("reports.passport.observed", { value: "" }).trim());
});

it("does not display source-quality values from a denied result", async () => {
  const raw = { ...definition, intent: passport };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? page({ state: "denied", items: [],
      coverage: { completeness: "complete", observed_at_utc: "2026-10-06T12:00:00Z" } }) : raw,
  ))));
  const view = renderReport();
  await screen.findByText(t("state.denied.title"));
  expect(view.container.querySelector("header")!.textContent).not.toContain(t("reports.passport.observed", { value: "" }).trim());
  expect(view.container.querySelector("header")!.textContent).not.toMatch(/Полнота|Completeness/i);
});

it.each(["not_collected", "partial", "processing", "stale", "error"] as const)("shows one empty or failed state for a rowless %s report", async (state) => {
  dataResponse.body = page({ state, items: [], state_details: { reason: "fixture-state", missing_sources: ["fixture-source"] } });
  const { container } = renderReport();
  await waitFor(() => expect(container.querySelector('[data-state="' + (state === "error" ? "error" : "empty") + '"]')).toBeTruthy());
  expect(container.querySelectorAll(".sli-ds-state")).toHaveLength(1);
  expect(screen.queryByText("fixture-source", { exact: false })).toBeNull();
});

it.each(["partial", "processing", "stale"] as const)("keeps available rows visible without a %s banner", async (state) => {
  dataResponse.body = page({ state });
  const { container } = renderReport();
  expect(await screen.findByText("DC1$")).toBeTruthy();
  expect(container.querySelector(".sli-ds-state")).toBeNull();
});

it.each(["partial", "processing", "stale"] as const)("shows one empty state for a rowless named collection in %s", async (state) => {
  const raw: ReportDefinitionDto = { ...definition, views: [{ kind: "table", key: "collection", source: "fixture-collection", note: "Synthetic collection note" }] };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?")
    ? page({ state, items: [], collections: { "fixture-collection": [] } }) : raw))));
  const { container } = renderReport();
  await waitFor(() => expect(container.querySelector('[data-state="empty"]')).toBeTruthy());
  expect(container.querySelectorAll(".sli-ds-state")).toHaveLength(1);
  expect(screen.queryByText("Synthetic collection note")).toBeNull();
});

it.each(["not_collected", "partial", "processing", "stale", "error"] as const)("keeps the passport with a single rowless %s state", async (state) => {
  const raw: ReportDefinitionDto = { ...definition, intent: passport, result_states: [state] };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? page({ state, items: [],
      coverage: { completeness: "complete", observed_at_utc: "2026-10-06T12:00:00Z" } }) : raw,
  ))));
  const { container } = renderReport();
  await waitFor(() => expect(container.querySelector('[data-state="' + (state === "error" ? "error" : "empty") + '"]')).toBeTruthy());
  const header = container.querySelector("header")!;
  expect(header.textContent).not.toContain(passport.question);
  expect(header.textContent).not.toContain(passport.denominator);
  expect(container.querySelectorAll(".sli-ds-state")).toHaveLength(1);
  expect(header.textContent).not.toMatch(/Полнота|Completeness/i);
});

it("identifies the table and retries a failed data request", async () => {
  dataResponse = { status: 503, body: { error: "fixture_failure" } };
  renderReport();
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("Не удалось загрузить «Демо-события»");
  expect(alert.hasAttribute("data-tone")).toBe(false);
  expect(alert.textContent).not.toContain("fixture_failure");
  dataResponse = { status: 200, body: page() };
  fireEvent.click(within(alert).getByRole("button", { name: t("state.retry") }));
  expect(await screen.findByRole("table", { name: "Демо-события" })).toBeTruthy();
});

it("retains report rows and read-only export without a disabled plugin badge", async () => {
  dataResponse = { status: 200, body: page({ plugin: { plugin_id: "sli.remote-access", state: "disabled", read_only: true } }) };
  renderReport();
  expect(await screen.findByText("DC1$")).toBeTruthy();
  expect(screen.queryByText(/Плагин выключен/)).toBeNull();
  expect(screen.getByRole("link", { name: "Экспорт CSV" })).toBeTruthy();
});

it.each([
  ["definition", "disabled", "ok", false],
  ["data", "disabled", "ok", false],
  ["data", "unknown", "ok", false],
  ["data", "enabled", "denied", false],
  ["data", "enabled", "ok", true],
] as const)("respects %s plugin state %s and report state %s for page actions", async (source, pluginState, reportState, visible) => {
  PAGE_ACTIONS["vpn.print-sheet"] = () => <button>Fixture action</button>;
  const plugin: NonNullable<ReportDefinitionDto["plugin"]> = { plugin_id: "sli.remote-access", state: pluginState, read_only: pluginState !== "enabled" };
  const raw: ReportDefinitionDto = { ...definition, page_actions: "vpn.print-sheet", ...(source === "definition" ? { plugin } : {}) };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const body = String(input).includes("/data?")
      ? page({ state: reportState, ...(source === "data" ? { plugin } : {}), access: { allowed: reportState !== "denied", hidden_categories: ["hr"] } })
      : raw;
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  }));

  renderReport();
  await screen.findByText("Часть колонок скрыта: нет доступа к категории кадровые сведения.");
  expect(Boolean(screen.queryByRole("button", { name: "Fixture action" }))).toBe(visible);
  expect(screen.queryByText(/Плагин выключен/)).toBeNull();
});

it("connects report tabs to the result panel, including empty states", async () => {
  const raw = { ...definition, views: [{ kind: "table", key: "table", title: "Rows" }, { kind: "chart", key: "daily", title: "Daily", source: "daily" }] };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? page({ state: "empty", items: [] }) : raw))));
  renderReport();
  const tab = await screen.findByRole("tab", { name: "Rows" });
  const panel = screen.getByRole("tabpanel");
  expect(tab.getAttribute("aria-controls")).toBe(panel.id);
  expect(panel.getAttribute("aria-labelledby")).toBe(tab.id);
  tab.focus();
  await userEvent.keyboard("{ArrowRight}");
  expect(document.activeElement).toBe(screen.getByRole("tab", { name: "Daily" }));
});

it("uses the last available instant to choose a calendar day in the report timezone", async () => {
  dataResponse.body = page({ state: "empty", items: [], coverage: { history_to_utc: "2026-09-01T23:30:00Z", source: { hostname: "sample-source" } },
    window: { from_utc: "2026-09-10T00:00:00Z", to_utc_exclusive: "2026-09-17T00:00:00Z" } });
  renderReport();
  const latest = await screen.findByRole("button", { name: "Показать последние данные" });
  expect(screen.getByText(/Последние доступные данные:/)).toBeTruthy();
  expect(screen.getByText(/Исходный период:/)).toBeTruthy();
  expect(screen.getByRole("link", { name: "Диагностика источника" }).getAttribute("href")).toBe("/app/operations/sources/sample-source");
  await userEvent.click(latest);
  await waitFor(() => expect(requested.some((url) => url.includes("period=custom"))).toBe(true));
  const params = new URL(requested.at(-1)!, "http://test").searchParams;
  expect(params.get("from")).toBe(params.get("to"));
  expect(params.get("from")).toBe("2026-09-02");
  expect(screen.getAllByText(/Исходный период:/).length).toBeGreaterThan(0);
});

it("offers general diagnostics for known coverage but does not invent a timestamp or source", async () => {
  dataResponse.body = page({ state: "empty", items: [], coverage: { state: "not_collected" } });
  renderReport();
  expect((await screen.findByRole("link", { name: "Диагностика источника" })).getAttribute("href")).toBe("/app/operations");
  expect(screen.queryByRole("button", { name: "Показать последние данные" })).toBeNull();
});

it("preserves empty copy when availability metadata is absent or invalid", async () => {
  dataResponse.body = page({ state: "empty", items: [], coverage: { history_to_utc: "invalid" } });
  renderReport();
  await screen.findByText("Ничего не найдено");
  expect(screen.queryByRole("button", { name: "Показать последние данные" })).toBeNull();
  expect(screen.queryByText(/Последние доступные данные:/)).toBeNull();
});

it("keeps the computer report's main controls visible and opens additional preset filters", async () => {
  const raw: ReportDefinitionDto = { ...definition, params: [
    { key: "view", label: "View", kind: "choice", default: "attention", options: [{ value: "attention", label: "Attention" }] },
    { key: "q", label: "Search", kind: "text" },
    { key: "type", label: "Type", kind: "choice", options: [{ value: "server", label: "Server" }] },
    { key: "threshold_days", label: "Threshold", kind: "choice", default: "60", options: [{ value: "60", label: "60 days" }] },
    { key: "os", label: "OS", kind: "text" }, { key: "ou", label: "OU", kind: "text" },
  ], presets: [{ label: "Servers", params: { type: "server" } }] };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? page({ metrics: [{ key: "total", label: "Total", value: 2 }] }) : raw))));
  renderReport();
  await screen.findByRole("table");
  const more = screen.getByText("Ещё фильтры").closest("details")!;
  expect(more.open).toBe(false);
  for (const label of ["View", "Search", "Threshold"]) expect(more.contains(screen.getByLabelText(label))).toBe(false);
  expect(more.contains(screen.getByLabelText("OS"))).toBe(true);
  expect(screen.getByRole("region", { name: "Сводка" }).getAttribute("data-compact")).toBe("true");
  await userEvent.click(screen.getByRole("button", { name: "Servers" }));
  await waitFor(() => expect(more.open).toBe(true));
  expect((screen.getByLabelText("Type") as HTMLSelectElement).value).toBe("server");
});

function mockVpnReport(preset = "7d") {
  const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [],
    views: [
      { key: "employees", kind: "table", title: "Сотрудники" },
      { key: "daily", kind: "table", source: "daily", title: "Динамика по дням" },
      { key: "authorizations", kind: "table", source: "authorizations", title: "Решения NPS" },
      { key: "windows", kind: "table", source: "windows", title: "Аутентификация Windows" },
    ],
  };
  window.history.replaceState(null, "", `/app/report/vpn.connections?domain=1&period=${preset}`);
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-05T12:34:56Z"));
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    const params = new URL(url, "http://test").searchParams;
    if (params.get("period") === "invalid") {
      return new Response(JSON.stringify({ error: "report_period_invalid" }), { status: 400, headers: { "Content-Type": "application/json" } });
    }
    const body = url.includes("/data?") ? page({ report_key: "vpn.connections",
      items: [{ id: params.get("cursor") ?? 1, actor: { name: "Synthetic principal" } }],
      has_more: !params.has("cursor") && !params.has("tab"), next_cursor: "next",
      window: { from_utc: params.get("from") ?? undefined, to_utc_exclusive: params.get("to") ?? undefined },
    }) : raw;
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  }));
}

describe("ReportRenderer", () => {
  it("preserves AD filters and exports when selecting a tab without duplicate shortcuts", async () => {
    const raw: ReportDefinitionDto = {
      ...definition, key: "ad.infrastructure", title: "Synthetic infrastructure",
      params: [
        { key: "view", kind: "choice", label: "Section", default: "overview", options: [{ value: "overview", label: "Overview" }, { value: "replication", label: "Replication" }] },
        { key: "qualification", kind: "choice", label: "Result", options: [{ value: "failed", label: "Failed" }] },
        { key: "entity_type", kind: "choice", label: "Type", options: [{ value: "replication_link", label: "Replication link" }] },
        { key: "q", kind: "text", label: "Search" },
        { key: "threshold_days", kind: "int", label: "Threshold", default: 30 },
      ],
      views: [{ kind: "table", key: "controls", title: "Controls" }, { kind: "table", key: "semantic", source: "semantic", title: "Findings", columns: [{ key: "title", path: "title", label: "Finding", kind: "text" }] }],
      presets: [{ label: "Synthetic replication", params: { view: "replication" } }],
    };
    window.history.replaceState(null, "", "/app/report/ad.infrastructure?tab=semantic&q=synthetic&qualification=failed&entity_type=replication_link&threshold_days=90");
    const rawPage = page({ collections: { semantic: [{ title: "Synthetic finding" }] }, metrics: [{ key: "failed", label: "Synthetic failures", value: 1, filter: { qualification: "failed" } }] });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      return new Response(JSON.stringify(url.includes("/data?") ? rawPage : raw), { status: 200, headers: { "Content-Type": "application/json" } });
    }));
    renderReport();
    await screen.findByRole("table", { name: "Findings" });
    const additional = screen.getByText(/Ещё фильтры/).closest("details")!;
    expect(additional.open).toBe(true);
    expect(additional.contains(screen.getByLabelText("Result"))).toBe(true);
    expect(additional.contains(screen.getByLabelText("Search"))).toBe(false);
    const initialExport = new URL(screen.getByRole("link", { name: "Экспорт CSV" }).getAttribute("href")!, "http://corp.example.test");
    expect(initialExport.searchParams.get("tab")).toBe("semantic");
    expect(screen.queryByRole("button", { name: "Synthetic replication" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Synthetic failures/ })).toBeNull();
    await userEvent.click(screen.getByRole("tab", { name: "Controls" }));
    await waitFor(() => expect(screen.getByRole("tab", { name: "Controls" }).getAttribute("aria-selected")).toBe("true"));
    expect(screen.getByRole("tabpanel").getAttribute("aria-labelledby")).toBe(screen.getByRole("tab", { name: "Controls" }).id);
    const params = new URLSearchParams(window.location.search);
    expect(params.get("q")).toBe("synthetic");
    expect(params.get("qualification")).toBe("failed");
    expect(params.get("entity_type")).toBe("replication_link");
    expect(params.get("threshold_days")).toBe("90");
    expect(params.get("view")).toBe("overview");
    const exported = new URL(screen.getByRole("link", { name: "Экспорт CSV" }).getAttribute("href")!, "http://corp.example.test").searchParams;
    expect(exported.get("tab")).toBe("controls");
    for (const [key, value] of params) expect(exported.get(key)).toBe(value);
    expect(exported.has("limit")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Сбросить" }));
    await waitFor(() => expect(new URLSearchParams(window.location.search).has("q")).toBe(false));
    expect(new URLSearchParams(window.location.search).get("threshold_days")).toBe("30");
  });

  it("resets grouped filters while preserving the selected domain and custom period", async () => {
    const raw: ReportDefinitionDto = { ...definition,
      params: [...definition.params, { key: "q", kind: "text", label: "Search" }, { key: "threshold_days", kind: "int", label: "Threshold", default: 30 }],
      filter_options: { domain: [{ value: "1", label: "example.test" }, { value: "2", label: "other.test" }] },
    };
    window.history.replaceState(null, "", "/app/report/demo.events?domain=2&period=custom&from=2026-09-10&to=2026-09-12&category=lock&q=synthetic&threshold_days=90");
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? page() : raw))));
    renderReport();
    await screen.findByRole("table");
    expect(screen.getByText(/Ещё фильтры/).closest("details")!.open).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "Сбросить" }));
    await waitFor(() => expect(new URLSearchParams(window.location.search).has("q")).toBe(false));
    expect(Object.fromEntries(new URLSearchParams(window.location.search))).toEqual({
      domain: "2", period: "custom", from: "2026-09-10", to: "2026-09-12", threshold_days: "30",
    });
    expect((screen.getByLabelText("Threshold") as HTMLInputElement).value).toBe("30");
  });

  it("exports the selected GPO scopes with the current conditions", async () => {
    const raw: ReportDefinitionDto = {
      ...definition, key: "ad.gpo.v2", title: "Synthetic policies",
      params: [{ key: "view", kind: "choice", label: "View", default: "attention", options: [{ value: "unlinked", label: "Unlinked" }] }, { key: "q", kind: "text", label: "Search" }],
      views: [{ kind: "table", key: "gpos", title: "Policies" }, { kind: "table", key: "linked_scopes", source: "linked_scopes", title: "Linked scopes", columns: [{ key: "label", path: "label", kind: "text", label: "Setting" }] }],
      presets: [],
    };
    window.history.replaceState(null, "", "/app/report/ad.gpo.v2?tab=linked_scopes&view=unlinked&q=synthetic");
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? page({ collections: { linked_scopes: [{ label: "Synthetic setting" }] } }) : raw), { status: 200, headers: { "Content-Type": "application/json" } })));
    renderReport();
    await screen.findByRole("table", { name: "Области применения" });
    const params = new URL(screen.getByRole("link", { name: "Экспорт CSV" }).getAttribute("href")!, "http://corp.example.test").searchParams;
    expect(params.get("tab")).toBe("linked_scopes");
    expect(params.get("view")).toBe("unlinked");
    expect(params.get("q")).toBe("synthetic");
    expect(params.has("cursor")).toBe(false);
    expect(params.has("limit")).toBe(false);
  });

  it.each([
    ["ru", false], ["en", false], ["ru", true], ["en", true],
  ] as const)("labels the general export outside the main view in %s with plugin disabled=%s", async (locale, disabled) => {
    setLocale(locale);
    PAGE_ACTIONS["vpn.print-sheet"] = () => <button>Fixture action</button>;
    const raw: ReportDefinitionDto = { ...definition, page_actions: "vpn.print-sheet", views: [{ kind: "table", key: "table", title: "Events" }, { kind: "table", key: "daily", source: "daily", title: "Daily", columns: [] }] };
    window.history.replaceState(null, "", "/app/report/demo.events?tab=daily");
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? page({ collections: { daily: [] }, plugin: { plugin_id: "sli.remote-access", state: disabled ? "disabled" : "enabled", read_only: disabled } }) : raw), { status: 200, headers: { "Content-Type": "application/json" } })));
    renderReport();
    const link = await screen.findByRole("link", { name: locale === "ru" ? "Экспорт CSV (все строки: Events)" : "Export CSV (all rows: Events)" });
    await waitFor(() => expect(Boolean(screen.queryByRole("button", { name: "Fixture action" }))).toBe(!disabled));
    expect(screen.queryByText(/Плагин выключен|Plugin disabled/i)).toBeNull();
    expect(new URL(link.getAttribute("href")!, "http://corp.example.test").searchParams.has("tab")).toBe(false);
  });

  it.each([
    ["ru", "Данные доступны", "Ошибка получения данных", "Нет доступа"],
    ["en", "Data available", "Data retrieval error", "No access"],
  ] as const)("shows independent VPN tab states and preserves NPS rows in %s", async (locale, available, unavailable, denied) => {
    setLocale(locale);
    const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [], views: [
      { kind: "table", key: "employees", title: "Accounting" },
      { kind: "table", key: "authorizations", source: "authorizations", title: "NPS", columns: [{ key: "decision", label: "Decision", kind: "text", path: "decision" }] },
      { kind: "table", key: "windows", source: "windows", title: "Windows" },
      { kind: "table", key: "windows_heatmap", source: "windows_heatmap", title: "Heatmap" },
    ] };
    window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1&tab=authorizations");
    const body = page({ report_key: "vpn.connections", state: "partial", items: [],
      branches: {
        accounting: { state: "error", reason: "source_unreadable", limitations: [{ code: "source_unreadable", text: "Accounting source unavailable" }] },
        nps: { state: "ok", reason: "available", limitations: [] },
        windows: { state: "denied", reason: "not_authorized", limitations: [{ code: "not_authorized", text: "Windows access denied" }] },
        windows_heatmap: { state: "error", reason: "source_unreadable", limitations: [] },
      }, collections: { authorizations: [{ decision: "Observed denial" }] },
    } as Partial<ReportResultDto>);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? body : raw), { status: 200, headers: { "Content-Type": "application/json" } })));
    renderReport("vpn.connections");
    expect(await screen.findByText("Observed denial")).toBeTruthy();
    const accountingTab = screen.getByRole("tab", { name: `${locale === "en" ? "Employees" : "Accounting"} ${unavailable}` });
    expect(accountingTab.getAttribute("aria-controls")).toBe(screen.getByRole("tabpanel").id);
    expect(screen.getByRole("tab", { name: `${locale === "en" ? "NPS decisions" : "NPS"} ${available}` })).toBeTruthy();
    screen.getByRole("tab", { name: `${locale === "en" ? "NPS decisions" : "NPS"} ${available}` }).focus();
    await userEvent.keyboard("{ArrowRight}");
    const windowsTab = screen.getByRole("tab", { name: `${locale === "en" ? "Windows authentication" : "Windows"} ${denied}` });
    expect(document.activeElement).toBe(windowsTab);
    expect(screen.getByRole("tabpanel").getAttribute("aria-labelledby")).toBe(windowsTab.id);
    expect((await screen.findByRole("alert")).textContent).toContain("Windows access denied");
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText(/Нет строк для этого представления|No rows for this view/)).toBeNull();
    await userEvent.click(screen.getByRole("tab", { name: `${locale === "en" ? "Employees" : "Accounting"} ${unavailable}` }));
    expect((await screen.findByRole("alert")).textContent).toContain("Accounting source unavailable");
    await userEvent.click(screen.getByRole("tab", { name: `${locale === "en" ? "NPS decisions" : "NPS"} ${available}` }));
    expect(await screen.findByText("Observed denial")).toBeTruthy();
  });

  it("keeps Accounting rows when NPS is unavailable and labels unopened sources", async () => {
    const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [], views: [
      { kind: "table", key: "employees", title: "Accounting" },
      { kind: "table", key: "authorizations", source: "authorizations", title: "NPS" },
      { kind: "table", key: "windows", source: "windows", title: "Windows" },
    ] };
    window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1");
    const body = page({ report_key: "vpn.connections", state: "partial",
      items: [{ id: 1, actor: { name: "Synthetic account" } }],
      branches: {
        accounting: { state: "ok", reason: "available", limitations: [] },
        nps: { state: "error", reason: "source_unreadable", limitations: [{ code: "source_unreadable", text: "Synthetic NPS unavailable" }] },
        windows: { state: "not_requested", reason: "load_on_open", limitations: [] },
      }, collections: { authorizations: [] },
    });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? body : raw), { status: 200, headers: { "Content-Type": "application/json" } })));
    renderReport("vpn.connections");
    expect(await screen.findByText("Synthetic account")).toBeTruthy();
    expect(screen.getByRole("tab", { name: "Windows Загрузка при открытии" })).toBeTruthy();
    await userEvent.click(screen.getByRole("tab", { name: "NPS Ошибка получения данных" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Synthetic NPS unavailable");
    expect(screen.queryByText("Нет строк для этого представления")).toBeNull();
    await userEvent.click(screen.getByRole("tab", { name: "Accounting Данные доступны" }));
    expect(await screen.findByText("Synthetic account")).toBeTruthy();
  });

  it("keeps VPN tabs reachable when the loaded Accounting branch is denied", async () => {
    const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", views: [
      { kind: "table", key: "employees", title: "Accounting" },
      { kind: "table", key: "authorizations", source: "authorizations", title: "NPS" },
    ] };
    window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1");
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const nps = new URL(url, window.location.origin).searchParams.get("tab") === "authorizations";
      const body = page({ report_key: "vpn.connections", state: nps ? "partial" : "denied", items: [],
        branches: {
          accounting: { state: "denied", reason: "not_authorized", limitations: [] },
          nps: { state: nps ? "empty" : "not_requested", reason: nps ? "available" : "load_on_open", limitations: [] },
        }, collections: { authorizations: [] },
      });
      return new Response(JSON.stringify(url.includes("/data?") ? body : raw), { status: 200, headers: { "Content-Type": "application/json" } });
    }));
    renderReport("vpn.connections");
    expect(await screen.findByRole("alert")).toBeTruthy();
    await userEvent.click(screen.getByRole("tab", { name: "NPS Загрузка при открытии" }));
    expect(await screen.findByRole("tab", { name: "NPS Данных в окне нет" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it.each(["definition", "api"] as const)("prioritizes a VPN %s access denial over cached branch status", async (denialSource) => {
    const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [],
      default_domain_id: 1, default_domain_state: "available", views: [
      { kind: "table", key: "employees", title: "Accounting" },
      { kind: "table", key: "windows", source: "windows", title: "Windows", access: denialSource === "definition" ? { allowed: false, reason: "report_scope_not_executable" } : undefined },
    ] };
    const body = page({ report_key: "vpn.connections", state: "partial", items: [{ id: 1, actor: { name: "Synthetic account" } }],
      branches: {
        accounting: { state: "ok", reason: "available", limitations: [] },
        windows: { state: "error", reason: "source_unreadable", limitations: [{ code: "source_unreadable", text: "Synthetic Windows source unavailable" }] },
      },
    });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      const denied = url.includes("tab=windows");
      return new Response(JSON.stringify(denied ? { error: "report_scope_not_executable" } : url.includes("/data?") ? body : raw), { status: denied ? 403 : 200, headers: { "Content-Type": "application/json" } });
    }));
    renderReport("vpn.connections");
    await screen.findByText("Synthetic account");
    await userEvent.click(screen.getByRole("tab", { name: "Windows Ошибка получения данных" }));
    expect(await screen.findByText("Разрешённая область не покрывает данные этой части отчёта.")).toBeTruthy();
    expect(screen.queryByText("Synthetic Windows source unavailable")).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
    expect(requested.some((url) => url.includes("tab=windows"))).toBe(denialSource === "api");
    await userEvent.click(screen.getByRole("tab", { name: /^Accounting/ }));
    expect(await screen.findByText("Synthetic account")).toBeTruthy();
  });

  it.each([
    ["ru", "Часть колонок скрыта: нет доступа к категории кадровые сведения.", "Нет доступа к категории кадровые сведения."],
    ["en", "Some columns are hidden: no access to category HR information.", "No access to category HR information."],
  ] as const)("explains hidden columns and denies only the selected tab in %s", async (locale, notice, denial) => {
    setLocale(locale);
    const raw = { ...definition, access: { allowed: true, hidden_categories: ["hr"], reason: "report_field_categories_not_allowed" },
      views: [{ key: "table", kind: "table" }, { key: "restricted", kind: "table", title: "Restricted tab", source: "restricted", access: { allowed: false, reason: "report_field_categories_not_allowed", hidden_categories: ["hr"] } }],
    };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      return new Response(JSON.stringify(url.includes("/data?") ? page() : raw), { status: 200, headers: { "Content-Type": "application/json" } });
    }));
    renderReport();
    await screen.findByRole("table");
    expect(screen.getByText(notice)).toBeTruthy();
    await userEvent.click(screen.getByRole("tab", { name: "Restricted tab" }));
    expect(await screen.findByText(denial)).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    expect(requested.some((url) => url.includes("tab=restricted"))).toBe(false);
    await userEvent.click(screen.getByRole("tab", { name: "table" }));
    expect(await screen.findByRole("table")).toBeTruthy();
  });

  it("denies an items tab independently and sends its key to the server", async () => {
    const raw = { ...definition, views: [{ key: "table", kind: "table" }, { key: "restricted", kind: "table", title: "Restricted tab" }] };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      const denied = url.includes("tab=restricted");
      const body = denied ? { error: "report_scope_not_executable", reason: "report_scope_not_executable", message: "untrusted-marker" } : url.includes("/data?") ? page() : raw;
      return new Response(JSON.stringify(body), { status: denied ? 403 : 200, headers: { "Content-Type": "application/json" } });
    }));
    renderReport();
    await screen.findByRole("table");
    await userEvent.click(screen.getByRole("tab", { name: "Restricted tab" }));
    expect(await screen.findByText("Разрешённая область не покрывает данные этой части отчёта.")).toBeTruthy();
    expect(screen.queryByText("untrusted-marker")).toBeNull();
    await userEvent.click(screen.getByRole("tab", { name: "table" }));
    expect(await screen.findByRole("table")).toBeTruthy();
  });

  it.each(["inline", "sub"] as const)("denies only %s details without requesting or rendering their rows", async (kind) => {
    const raw = { ...definition, detail: { kind, title: "Restricted detail", key: "id", inline: "reasons", columns: [], row_links: [],
      access: { allowed: false, reason: "report_access_denied" } } };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      return new Response(JSON.stringify(url.includes("/data?") ? page() : raw), { status: 200, headers: { "Content-Type": "application/json" } });
    }));
    renderReport();
    await userEvent.click(await screen.findByText("DC1$"));
    expect(await screen.findByText("Нет права на запрошенную часть отчёта.")).toBeTruthy();
    expect(requested.some((url) => url.includes("/detail"))).toBe(false);
    expect(screen.getByRole("table")).toBeTruthy();
  });

  it("explains a detail API denial while retaining the main report", async () => {
    const raw = { ...definition, detail: { kind: "sub", title: "Restricted detail", key: "id", columns: [], row_links: [] } };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const denied = url.includes("/detail");
      return new Response(JSON.stringify(denied ? { error: "report_access_denied" } : url.includes("/data?") ? page() : raw), { status: denied ? 403 : 200, headers: { "Content-Type": "application/json" } });
    }));
    renderReport();
    await userEvent.click(await screen.findByText("DC1$"));
    expect(await screen.findByText("Нет права на запрошенную часть отчёта.")).toBeTruthy();
    expect(screen.getByRole("table")).toBeTruthy();
  });

  it("lets the server reject an unknown VPN preset without crashing the renderer", async () => {
    mockVpnReport("invalid");
    renderReport("vpn.connections");
    expect((await screen.findByRole("alert")).textContent).toContain("report_period_invalid");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it.each([
    ["ru", ["Динамика по дням", "Решения NPS", "Аутентификация Windows"], "Показать ещё", "Экспорт CSV (все строки: Сотрудники)",
      "Accounting, NPS и Windows используют одно точное окно; верхняя граница не включается."],
    ["en", ["Daily trend", "NPS decisions", "Windows authentication"], "Show more", "Export CSV (all rows: Employees)",
      "Accounting, NPS and Windows use the same exact window; the upper bound is excluded."],
  ] as const)("keeps the same 168-hour VPN window across tabs, pagination and export in %s", async (locale, tabs, more, exportLabel, note) => {
    setLocale(locale);
    mockVpnReport();
    renderReport("vpn.connections");
    expect(await screen.findByText(note)).toBeTruthy();
    const first = new URL(requested.find((url) => url.includes("/data?"))!, "http://test").searchParams;
    expect(first.get("period")).toBe("custom");
    expect(first.get("from")).toBe("2026-09-28T12:34:56.000Z");
    expect(first.get("to")).toBe("2026-10-05T12:34:56.000Z");
    expect(new Date(first.get("to")!).getTime() - new Date(first.get("from")!).getTime()).toBe(168 * 3_600_000);
    // Time advancing between requests must not move the selected window.
    vi.setSystemTime(new Date("2026-10-06T15:00:00Z"));
    await userEvent.click(screen.getByRole("button", { name: more }));
    await waitFor(() => expect(requested.some((url) => url.includes("cursor=next"))).toBe(true));
    for (const [index, tab] of tabs.entries()) {
      await userEvent.click(screen.getByRole("tab", { name: tab }));
      const key = ["daily", "authorizations", "windows"][index];
      await waitFor(() => expect(requested.some((url) => new URL(url, "http://test").searchParams.get("tab") === key)).toBe(true));
    }
    const exportUrl = screen.getByRole("link", { name: exportLabel }).getAttribute("href")!;
    const exportParams = new URL(exportUrl, "http://test").searchParams;
    for (const key of ["tab", "cursor", "limit"]) expect(exportParams.has(key)).toBe(false);
    for (const url of [...requested.filter((url) => url.includes("/data?")), exportUrl]) {
      const params = new URL(url, "http://test").searchParams;
      expect([params.get("from"), params.get("to")]).toEqual([first.get("from"), first.get("to")]);
    }
    expect(window.location.search).toContain("period=7d");
  });

  it("resolves a newly applied VPN preset and leaves custom calendar dates for the server timezone contract", async () => {
    mockVpnReport();
    renderReport("vpn.connections");
    await screen.findByRole("table");
    vi.setSystemTime(new Date("2026-10-06T15:00:00Z"));
    await userEvent.click(screen.getByRole("radio", { name: "24 часа" }));
    await userEvent.click(screen.getByRole("button", { name: "Применить" }));
    await waitFor(() => expect(requested.some((url) => new URL(url, "http://test").searchParams.get("from") === "2026-10-05T15:00:00.000Z")).toBe(true));
    expect(new URL(requested.at(-1)!, "http://test").searchParams.get("to")).toBe("2026-10-06T15:00:00.000Z");
    await userEvent.click(screen.getByRole("radio", { name: "Свой период" }));
    fireEvent.change(screen.getByLabelText("С"), { target: { value: "2026-09-14" } });
    fireEvent.change(screen.getByLabelText("По"), { target: { value: "2026-09-14" } });
    await userEvent.click(screen.getByRole("button", { name: "Применить" }));
    await waitFor(() => expect(requested.some((url) => new URL(url, "http://test").searchParams.get("from") === "2026-09-14")).toBe(true));
    const params = new URL(requested.at(-1)!, "http://test").searchParams;
    expect([params.get("period"), params.get("from"), params.get("to")]).toEqual(["custom", "2026-09-14", "2026-09-14"]);
  });

  it("renders the selected collection when the main table is empty", async () => {
    const raw = { ...definition, views: [{ key: "semantic", kind: "table", source: "semantic", title: "Related findings", columns: [{ key: "label", label: "Finding", path: "label", kind: "text" }] }] };
    const rawPage = page({ state: "empty", items: [], collections: { semantic: [{ label: "Synthetic finding" }] } });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? rawPage : raw), { status: 200, headers: { "Content-Type": "application/json" } })));
    renderReport();
    expect(await screen.findByRole("table", { name: "Related findings" })).toBeTruthy();
    expect(screen.getByText("Synthetic finding")).toBeTruthy();
    expect(screen.queryByText("Ничего не найдено")).toBeNull();
  });

  it("localizes fetched metadata in English without translating entity values", async () => {
    setLocale("en");
    const raw = { ...definition, key: "security.events.chains", title: "Действия безопасности", description: "События безопасности контроллеров домена: блокировки, изменения учётных записей и групп, пароли, аудит.",
      params: definition.params.map((param) => param.key === "category" ? { ...param, options: [{ value: "account_lock", label: "Updated option" }] } : param),
      columns: definition.columns.map((column) => column.key === "family" ? { ...column, labels: { account_lock: "Updated label" } } : column.key === "who" ? { ...column, key: "actor" } : column),
      presets: [{ label: "Updated preset", params: { category: "account_lock", event_id: "4740" } }],
    };
    const rawPage = page({ report_key: "security.events.chains", items: [{ id: 5, actor: { name: "Политика" }, family: "account_lock" }], metrics: [{ key: "future", label: "Updated metric", value: 1 }] });
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? rawPage : raw), { status: 200, headers: { "Content-Type": "application/json" } })));
    renderReport();
    const table = await screen.findByRole("table", { name: "Domain changes" });
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Domain changes");
    expect(screen.queryByText("Updated metric")).toBeNull();
    expect(within(table).getByRole("columnheader", { name: "Who" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Lockouts" })).toBeTruthy();
    expect(within(table).getByText("Lockout and unlock")).toBeTruthy();
    expect(within(table).getByText("Политика")).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Breadcrumbs" })).toBeTruthy();
  });

  it("builds the page from the declaration and shows server rows with labels", async () => {
    renderReport();
    const table = await screen.findByRole("table", { name: "Демо-события" });
    expect(within(table).getByText("DC1$")).toBeTruthy();
    expect(within(table).getByText("Блокировка")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Демо-события");
    const dataUrl = requested.find((url) => url.includes("/data?"))!;
    expect(new URL(dataUrl, "http://corp.example.test").searchParams.get("domain")).toBe("1");
    expect(new URL(dataUrl, "http://corp.example.test").searchParams.get("period")).toBe("7d");
    expect(window.location.search).toBe("?domain=1&period=7d");
  });

  it("applies a quick scenario and requests the matching data", async () => {
    renderReport();
    await screen.findByRole("table");
    await userEvent.click(screen.getByRole("button", { name: "Только блокировки" }));
    await waitFor(() => expect(requested.some((url) => url.includes("category=lock"))).toBe(true));
    expect(window.location.search).toContain("category=lock");
  });

  it("opens row details with a link that returns to the report", async () => {
    renderReport();
    await userEvent.click(await screen.findByText("DC1$"));
    const dialog = screen.getByRole("dialog");
    const link = within(dialog).getByRole("link", { name: "Карточка события" });
    expect(link.getAttribute("href")).toMatch(/^\/app\/events\/5\?return_to=%2Fapp%2Freport%2Fdemo\.events/);
  });

  it("shows denial instead of an empty table when the server refuses", async () => {
    dataResponse = { status: 403, body: { error: "report_access_denied" } };
    renderReport();
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Нет доступа");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("explains an engine denial returned as a result state", async () => {
    dataResponse = { status: 200, body: page({ state: "denied", items: [], access: { allowed: false, reason: "report_scope_not_executable" } }) };
    renderReport();
    expect(await screen.findByText("Разрешённая область не покрывает данные этой части отчёта.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it.each([
    ["ru", "Сохранённый снимок групповых политик недоступен или повреждён. Необходимо проверить источник и повторить сбор снимка."],
    ["en", "The saved Group Policy snapshot is unavailable or damaged. Check the source and collect the snapshot again."],
  ] as const)("explains snapshot unavailability in %s without blaming request parameters", async (locale, detail) => {
    setLocale(locale);
    dataResponse = { status: 503, body: { error: "gpo_snapshot_unavailable", state: "error", reason: "source_contract_error" } };
    renderReport();
    expect(await screen.findByText(detail)).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText(/отклонил параметры|rejected request parameters/)).toBeNull();
    expect(screen.queryByText(/Ничего не найдено|Nothing found/)).toBeNull();
  });

  it("keeps an honest empty state with the server's limitations", async () => {
    dataResponse = { status: 200, body: page({ state: "empty", items: [], limitations: [{ code: "empty_not_proof", text: "Пустой результат не доказывает полноту." }] }) };
    renderReport();
    const status = await screen.findByText("Ничего не найдено");
    expect(status).toBeTruthy();
  });

  it.each([
    ["ru", "Ничего не найдено"],
    ["en", "Nothing found"],
  ] as const)("shows the localized empty state instead of a bare table when a ready result has no rows in %s", async (locale, title) => {
    setLocale(locale);
    dataResponse = { status: 200, body: page({ state: "ok", items: [], limitations: [{ code: "partial_source", text: "Источник подтверждён частично." }] }) };
    renderReport();
    expect(await screen.findByText(title)).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getByText("Источник подтверждён частично.")).toBeTruthy();
  });

  it("names the report in the empty text so empty reports are not one identical stub", async () => {
    dataResponse = { status: 200, body: page({ state: "ok", items: [] }) };
    renderReport();
    expect(await screen.findByText(/В отчёте «.+», в таблице «.+» по выбранным условиям записей нет/)).toBeTruthy();
  });
});

it.each(["ru", "en"] as const)("retries an incomplete VPN timeout without losing rows or the 90-day request in %s", async (locale) => {
  setLocale(locale);
  const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [], views: [
    { kind: "table", key: "authorizations", source: "authorizations", title: "NPS", columns: [{ key: "decision", label: "Decision", kind: "text", path: "decision" }] },
  ] };
  window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1&period=90d&tab=authorizations");
  const note = { code: "source_read_timeout", text: "Чтение заняло слишком много времени. Результат неполный; показаны только полученные данные. Повторите попытку или сократите период." };
  const partial = page({ report_key: raw.key, state: "partial", items: [], limitations: [note],
    branches: { nps: { state: "partial", reason: "source_read_timeout", limitations: [note] } },
    collections: { authorizations: [{ decision: "Retained synthetic denial" }] },
  });
  let finishRetry: ((response: Response) => void) | undefined;
  const requests: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (!url.includes("/data?")) return new Response(JSON.stringify(raw));
    requests.push(url);
    if (requests.length === 1) return new Response(JSON.stringify(partial));
    return new Promise<Response>((resolve) => { finishRetry = resolve; });
  }));
  renderReport(raw.key);
  expect(await screen.findByText("Retained synthetic denial")).toBeTruthy();
  const retry = screen.getByRole("button", { name: t("state.retry") });
  expect(screen.queryByText(t("reports.v2.vpn.connections.limitations.source_read_timeout"), { exact: false })).toBeNull();
  expect(requests).toHaveLength(1);
  await userEvent.click(retry);
  await waitFor(() => expect(requests).toHaveLength(2));
  expect(retry.hasAttribute("disabled")).toBe(true);
  expect(screen.getByText("Retained synthetic denial")).toBeTruthy();
  expect(requests[1]).toBe(requests[0]);
  const query = new URL(requests[1], "http://localhost").searchParams;
  expect(Date.parse(query.get("to")!) - Date.parse(query.get("from")!)).toBe(90 * 86400000);
  finishRetry!(new Response(JSON.stringify({ ...partial, state: "ok", limitations: [],
    branches: { nps: { state: "ok", reason: "available", limitations: [] } },
    collections: { authorizations: [{ decision: "Retried synthetic denial" }] },
  })));
  expect(await screen.findByText("Retried synthetic denial")).toBeTruthy();
  expect(screen.queryByRole("button", { name: t("state.retry") })).toBeNull();
});

it.each(["ru", "en"] as const)("explains a VPN HTTP read deadline in %s instead of a generic error", async (locale) => {
  setLocale(locale);
  const raw: ReportDefinitionDto = { ...definition, key: "vpn.connections", presets: [] };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const failed = String(input).includes("/data?");
    return new Response(JSON.stringify(failed ? { error: "report_read_timeout" } : raw), { status: failed ? 503 : 200 });
  }));
  window.history.replaceState(null, "", "/app/report/vpn.connections?domain=1");
  renderReport(raw.key);
  expect(await screen.findByText(t("reports.v2.vpn.connections.limitations.source_read_timeout"))).toBeTruthy();
  expect(screen.getByRole("button", { name: t("state.retry") })).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
});


it.each(['ru', 'en'] as const)('keeps rule-quality identifiers in the inline drawer only in %s', async (locale) => {
  setLocale(locale);
  const metrics = { closed: 2, accepted_risk: null, suppressed: 0, classified: 3, median_decision_seconds: 3600, decided: 4, repeat_rate: 25 };
  const raw: ReportDefinitionDto = { ...definition, key: 'security.rule-quality', params: [], presets: [], row_links: [], row_key: 'rule_code',
    columns: [{ key: 'rule_name', label: 'Правило', kind: 'text', path: 'rule_name', link: '/app/report/security.problems?rule_code={rule_code}&created_from={cohort_from}&created_to={cohort_to}&show_suppressed=true' },
      { key: 'findings_produced', label: 'Создано находок', kind: 'number', path: 'findings_produced' },
      { key: 'false_positive_rate', label: 'Ложные срабатывания, %', kind: 'number', path: 'false_positive_rate' }],
    detail: { title: 'Технические сведения', key: 'rule_code', kind: 'inline', inline: 'technical_details', row_links: [],
      columns: [{ key: 'rule_code', label: 'Код правила', kind: 'text', path: 'rule_code' }, { key: 'policies', label: 'Текущие версии политик (контекст)', kind: 'list', path: 'policies' }, ...Object.keys(metrics).map(key => ({ key, label: ru[`reports.v2.security.rule-quality.detail.columns.${key}.label` as keyof typeof ru], kind: 'number' as const, path: key }))] } };
  const body = page({ report_key: raw.key, items: ['semantic.synthetic-one', 'semantic.synthetic-two'].map(rule_code => ({ rule_code,
    rule_name: 'Название правила недоступно', presentation_messages: { rule_name: { code: 'reports.v2.security.rule-quality.names.unknown', params: {}, text: 'Название правила недоступно' } },
    findings_produced: 3, false_positive_rate: null, cohort_from: '2026-10-01T00:00:00+00:00', cohort_to: '2026-10-08T00:00:00+00:00',
    technical_details: [{ rule_code, policies: ['synthetic-policy:7'], ...metrics }],
  })) });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input); requested.push(url);
    return new Response(JSON.stringify(url.includes('/data?') ? body : raw), { headers: { 'Content-Type': 'application/json' } });
  }));
  renderReport(raw.key);
  const links = await screen.findAllByRole('link', { name: t('reports.v2.security.rule-quality.names.unknown') });
  expect(links).toHaveLength(2);
  expect(screen.queryByText('semantic.synthetic-one')).toBeNull();
  expect(screen.queryByText('synthetic-policy:7')).toBeNull();
  const target = new URL(links[0].getAttribute('href')!, window.location.origin);
  expect(target.searchParams.get('rule_code')).toBe('semantic.synthetic-one');
  expect(target.searchParams.get('created_from')).toBe('2026-10-01T00:00:00+00:00');
  expect(target.searchParams.get('created_to')).toBe('2026-10-08T00:00:00+00:00');
  expect(target.searchParams.get('show_suppressed')).toBe('true');
  fireEvent.click(links[0].closest('tr')!);
  const drawer = await screen.findByRole('dialog');
  expect(within(drawer).getByText('semantic.synthetic-one')).toBeTruthy();
  expect(within(drawer).getByText('synthetic-policy:7')).toBeTruthy();
  const messages = locale === 'ru' ? ru : en;
  for (const key of Object.keys(metrics)) {
    const label = messages[`reports.v2.security.rule-quality.detail.columns.${key}.label` as keyof typeof messages];
    expect(label).toBeTruthy();
    expect(within(drawer).getByRole('columnheader', { name: label })).toBeTruthy();
  }
  for (const value of ['2', '—', '0', '3', '4', '25']) expect(within(drawer).getByRole('cell', { name: value })).toBeTruthy();
  fireEvent.keyDown(drawer, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  fireEvent.click(links[1].closest('tr')!);
  const reopened = await screen.findByRole('dialog');
  expect(within(reopened).getByText('semantic.synthetic-two')).toBeTruthy();
  expect(within(reopened).queryByText('semantic.synthetic-one')).toBeNull();
  expect(requested.some(url => url.includes('/rows/'))).toBe(false);
});

it.each(["ru", "en"] as const)("shows workstation operations without changing source evidence (%s)", async (locale) => {
  setLocale(locale);
  const raw: ReportDefinitionDto = { ...definition, key: "workstations.logons", params: [], presets: [], row_links: [],
    columns: [
      { key: "event_id", path: "event_id", label: "Event", kind: "number" },
      { key: "semantic_type", path: "semantic_type", label: "Type", kind: "text" },
      { key: "logon_type", path: "facts.logon_type", label: "Logon", kind: "text" },
    ] };
  const body = page({ report_key: raw.key, items: [{ id: "synthetic-observation", event_id: 4624,
    semantic_type: "authentication.session.created", facts: { logon_type: "10" } }] });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(
    JSON.stringify(String(input).includes("/data?") ? body : raw), { headers: { "Content-Type": "application/json" } },
  )));
  renderReport(raw.key);
  const operation = await screen.findByText(locale === "ru" ? "Вход в систему" : "Signed in");
  expect(screen.getByText(locale === "ru" ? "Удалённый интерактивный вход" : "Remote interactive sign-in")).toBeTruthy();
  expect(screen.queryByText("authentication.session.created")).toBeNull();
  expect(screen.queryByText("4 624")).toBeNull();
  fireEvent.click(operation);
  expect(await screen.findByText("authentication.session.created")).toBeTruthy();
  expect(screen.getByText("10")).toBeTruthy();
  expect(body.items[0]).toEqual({ id: "synthetic-observation", event_id: 4624,
    semantic_type: "authentication.session.created", facts: { logon_type: "10" } });
});

it("does not infer a workstation operation from an event number with mismatched semantics", async () => {
  const raw: ReportDefinitionDto = { ...definition, key: "workstations.logons", params: [], presets: [], row_links: [],
    columns: [{ key: "event_id", path: "event_id", label: "Event", kind: "number" },
      { key: "semantic_type", path: "semantic_type", label: "Type", kind: "text" }] };
  const body = page({ report_key: raw.key, items: [{ id: "synthetic-observation", event_id: 4624, semantic_type: "synthetic.unknown" }] });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(
    JSON.stringify(String(input).includes("/data?") ? body : raw), { headers: { "Content-Type": "application/json" } },
  )));
  renderReport(raw.key);
  const operation = await screen.findByText("Название операции не определено");
  expect(screen.queryByText("Вход в систему")).toBeNull();
  fireEvent.click(operation);
  expect(await screen.findByText("synthetic.unknown")).toBeTruthy();
});


it.each(["ru", "en"] as const)("restores a process fact column on pagination while retaining details and export (%s)", async (locale) => {
  setLocale(locale);
  vi.spyOn(appContext, "useTimeZone").mockReturnValue({ timeZone: "UTC", setTimeZone: vi.fn() });
  const raw: ReportDefinitionDto = { ...definition, key: "workstations.processes", section: "reports/workstations",
    params: [], presets: [], row_links: [], description: "", columns: [
      { key: "process_image", label: "Synthetic process", kind: "text", path: "facts.process_image" },
      { key: "service_name", label: "Synthetic service", kind: "text", path: "facts.service_name" },
      { key: "task_name", label: "Synthetic task", kind: "text", path: "facts.task_name" },
    ],
  };
  // The API localizes known column keys in English, preserving server labels in Russian.
  const serviceLabel = locale === "en" ? "Service" : "Synthetic service";
  const taskLabel = locale === "en" ? "Task" : "Synthetic task";
  const originalColumns = JSON.stringify(raw.columns);
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    const second = new URL(url, window.location.origin).searchParams.get("cursor") === "next-process";
    const body = page({ report_key: raw.key, items: second
      ? [{ id: "process-two", facts: { process_image: "synthetic-two.exe", service_name: "Synthetic observed service" } }]
      : [{ id: "process-one", facts: { process_image: "synthetic-one.exe" } }],
      has_more: !second, next_cursor: second ? null : "next-process" });
    return new Response(JSON.stringify(url.includes("/data?") ? body : raw), { headers: { "Content-Type": "application/json" } });
  }));
  renderReport(raw.key);
  await screen.findByText("synthetic-one.exe");
  const table = screen.getByRole("table");
  expect(within(table).queryByRole("columnheader", { name: serviceLabel })).toBeNull();
  expect(within(table).queryByRole("columnheader", { name: taskLabel })).toBeNull();
  const exportHref = screen.getByRole("link", { name: t("reports.renderer.export_csv") }).getAttribute("href");
  expect(exportHref).toContain("/api/v2/reports/workstations.processes/export.csv?");
  fireEvent.click(screen.getByText("synthetic-one.exe"));
  const drawer = await screen.findByRole("dialog");
  expect(within(drawer).getByText(serviceLabel)).toBeTruthy();
  expect(within(drawer).getByText(taskLabel)).toBeTruthy();
  fireEvent.keyDown(drawer, { key: "Escape" });
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  fireEvent.click(screen.getByRole("button", { name: t("table.loadMore") }));
  await screen.findByText("synthetic-two.exe");
  expect(within(screen.getByRole("table")).getByRole("columnheader", { name: serviceLabel })).toBeTruthy();
  expect(within(screen.getByRole("table")).queryByRole("columnheader", { name: taskLabel })).toBeNull();
  expect(screen.getByText("Synthetic observed service")).toBeTruthy();
  expect(screen.getByRole("link", { name: t("reports.renderer.export_csv") }).getAttribute("href")).toBe(exportHref);
  expect(JSON.stringify(raw.columns)).toBe(originalColumns);
});



it.each((["ru", "en"] as const).flatMap((locale) => [false, true].map((withPassport) => ({ locale, withPassport }))))("keeps the report archive context in closed details without workspace access ($locale, passport=$withPassport)", async ({ locale, withPassport }) => {
  setLocale(locale);
  vi.spyOn(appContext, "useTimeZone").mockReturnValue({ timeZone: "UTC", setTimeZone: vi.fn() });
  vi.spyOn(appContext, "useEffectiveAccess").mockReturnValue({ capabilities: [] } as unknown as ReturnType<typeof appContext.useEffectiveAccess>);
  const raw = withPassport ? { ...definition, intent: passport } : definition;
  const body = page({ domains: [{ id: 1, display_name: "archive.example.test", is_archived: true, freshness: { observed_at_utc: "2026-10-12T00:00:00Z" } }], coverage: { domains: [{ domain_id: 1, observed_at_utc: "2026-09-01T00:00:00Z" }] } });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? body : raw), { headers: { "Content-Type": "application/json" } })));
  renderReport();
  await screen.findByText("DC1$");
  const context = screen.getByText(/archive\.example\.test/);
  const detail = context.closest("details");
  expect(detail).not.toBeNull();
  expect(detail?.open).toBe(false);
  expect(context.textContent).toContain(locale === "ru" ? "01.09.2026" : "Sep 1, 2026");
  expect(context.textContent).not.toContain(locale === "ru" ? "12.10.2026" : "Oct 12, 2026");
  expect(body.coverage).toMatchObject({ domains: [{ observed_at_utc: "2026-09-01T00:00:00Z" }] });
  expect(context.textContent).toContain(t("domain.archive.coverage"));
  expect(context.closest('[role="status"]')).toBeNull();
});

it.each((["ru", "en"] as const).flatMap(locale => ["ok", "empty", "partial", "not_collected"].map(state => ({ locale, state }))))("explains USB empty collection in $locale / $state", async ({ locale, state }) => {
  setLocale(locale);
  const raw: ReportDefinitionDto = { ...definition, key: "workstations.usb", params: [], presets: [], columns: [{ key: "host_name", label: "Computer", kind: "text", path: "host_name" }], views: [{ key: "table", kind: "table", source: "items" }] };
  const body = page({ report_key: raw.key, state: state as ReportResultDto["state"], items: [], coverage: { state: "not_proven" } });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? body : raw), { headers: { "Content-Type": "application/json" } })));
  renderReport(raw.key);
  if (state === "not_collected") {
    const link = await screen.findByRole("link", { name: t("agents.title") });
    expect(link.getAttribute("href")).toBe("/app/agents");
  }
  await waitFor(() => expect(document.querySelector('[data-state="empty"]')).toBeTruthy());
  expect(document.querySelectorAll(".sli-ds-state")).toHaveLength(1);
});


it.each(["ru", "en"] as const)("keeps user and computer inventories free of source warnings and view notes (%s)", async (locale) => {
  setLocale(locale);
  for (const [key, tab] of [["ad.users.v2", "all"], ["ad.computers.v6", "computers"]]) {
    const raw: ReportDefinitionDto = { ...definition, key, params: [], presets: [],
      columns: [{ key: "name", label: "Object", path: "name", kind: "text" }],
      views: [{ key: tab, kind: "table", note: "Synthetic inventory note" }] };
    const body = page({ report_key: key, state: "partial", items: [{ id: 1, name: "synthetic-object", sam: "synthetic-object" }],
      coverage: { domains: [{ domain_name: "warning.example.test", observed_at_utc: null, state: "not_collected" }],
        truncated: true, events_truncated: true, computer_snapshot_observed_at_utc: "2020-01-01T00:00:00Z" } });
    window.history.replaceState(null, "", `/app/report/${key}?tab=${tab}`);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(String(input).includes("/data?") ? body : raw))));
    const { container } = renderReport(key);
    await screen.findByText("synthetic-object");
    expect(container.querySelector('.sli-ds-callout[data-tone="warning"]')).toBeNull();
    expect(container.querySelector(".sli-ds-state")).toBeNull();
    expect(screen.queryByText("warning.example.test", { exact: false })).toBeNull();
    expect(screen.queryByText("Synthetic inventory note")).toBeNull();
    cleanup();
  }
});
