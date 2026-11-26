// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { chooseOption } from "../../../tests/select-option";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { ReportRenderer } from "../../app/report-v2/ReportRenderer";
import { ComputerChecks, computerRole, computerTableColumns } from "./ComputerChecks";
import { DataTable, OverlayProvider } from "../../design-system";
import { formatDateTime } from "../../shared/date-time";
import { DEFAULT_TIME_ZONE } from "../../shared/time-zone";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";

const effective = vi.hoisted(() => ({ reports: [] as { report_key: string; allowed: boolean }[], capabilities: [] as string[] }));
vi.mock("../../app/App", async (load) => ({
  ...(await load<typeof import("../../app/App")>()),
  useEffectiveAccess: () => effective,
}));

const columns: ReportDefinitionDto["columns"] = [
  { key: "display_name", path: "display_name", label: "Компьютер", kind: "text", link: "/app/entities/{entity_id}" },
  { key: "computer_type", path: "computer_type", label: "Тип", kind: "state", labels: { server: "Сервер", domain_controller: "Контроллер домена" } },
  { key: "operating_system", path: "operating_system", label: "ОС", kind: "text" },
  { key: "laps_state", path: "laps_state", label: "LAPS", kind: "state", hidden_by_default: true },
];
const definition: ReportDefinitionDto = {
  key: "ad.computers.v6", title: "Компьютеры", description: "", section: "reports/computers", archetype: "inventory-status",
  params: [{ key: "view", label: "Срез", kind: "choice", hidden: true, default: "all" },
    { key: "domain_id", label: "Домен", kind: "domain", hidden: true }, { key: "q", label: "Поиск", kind: "text" },
    { key: "type", label: "Тип", kind: "choice", options: [{ value: "domain_controller", label: "Контроллер домена" }] }],
  columns, views: [{ key: "checks", title: "Требуют проверки", kind: "table", source: "checks" },
    { key: "changes", title: "Изменения", kind: "table", source: "changes", note: "Synthetic computer changes note", columns: [...columns.slice(0, 2),
      { key: "change_type", path: "change_type", label: "Изменение", kind: "text" },
      { key: "before", path: "before", label: "Было", kind: "text" }, { key: "after", path: "after", label: "Стало", kind: "text" }] },
    { key: "computers", title: "Все компьютеры", kind: "table" }],
  row_key: "entity_id", detail: { kind: "inline", key: "entity_id", title: "Почему на проверке", inline: "reasons", row_links: [],
    columns: [{ key: "label", path: "label", label: "Причина", kind: "text" }] },
  export: true, limits: { default: 50, max: 200 }, presets: [], row_links: [], filter_options: {},
};
const host = { entity_id: 1, domain_id: 8, object_guid: "00000000-0000-0000-0000-000000000001", display_name: "synthetic-host", domain_name: "example.test", computer_type: "domain_controller", operating_system: "unknown", reasons: [] };
const check = { id: "computers:laps", key: "laps", title: "Synthetic LAPS check", severity: "medium", severity_text: "Средняя",
  status: "not_evaluated", status_text: "Не оценено", total: 4, new_count: null, is_lower_bound: true, remaining_objects: 1,
  why: "Synthetic reason", action: "Synthetic action", remediation: "Synthetic remediation",
  objects: [{ name: "synthetic-preview", domain_name: "example.test", computer_type: "server" }] };
const page = (overrides: Partial<ReportResultDto> = {}): ReportResultDto => ({
  contract_id: "sli.report-result.v2", report_key: definition.key, state: "partial", items: [check],
  filtered_count: 1, has_more: false, next_cursor: null, metrics: [], series: {}, limitations: [], filter_options: {}, window: {},
  coverage: { population: 4, affected_objects: 4, not_evaluated_count: 1,
    domains: [{ domain_id: 8, domain_name: "example.test", state: "complete", observed_at_utc: new Date().toISOString() }] }, ...overrides,
});
const requests: URLSearchParams[] = [];
let respond: (params: URLSearchParams) => ReportResultDto;
let respondTo: (url: URL) => unknown;
function show(props: Partial<Parameters<typeof ReportRenderer>[0]> = {}) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><OverlayProvider><ReportRenderer reportKey={definition.key} {...props}/></OverlayProvider></QueryClientProvider>);
}
beforeEach(() => {
  requests.length = 0;
  effective.reports = [];
  effective.capabilities = [];
  respondTo = () => undefined;
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?domain_id=8&tab=checks");
  respond = (params) => params.get("tab") === "checks" ? page() : params.get("tab") === "changes"
    ? page({ items: [{ ...host, row_id: "new:1", change_type: "Synthetic discovery", before: "Absent", after: "Present" }] })
    : page({ state: "ok", items: [host], metrics: [{ key: "all", label: "All", value: 1 }], coverage: {} });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const params = new URL(url, "http://example.test").searchParams;
    if (url.includes("/data?")) requests.push(params);
    const response = respondTo(new URL(url, "http://example.test")) ?? (url.includes("/data?") ? respond(params) : definition);
    return new Response(JSON.stringify(response));
  }));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("preserves declared links and their return query outside the computer name overlay", () => {
  const onSelect = vi.fn();
  const row = { ...host, related: { id: 7, name: "synthetic-object" } };
  const linkedColumns: ReportDefinitionDto["columns"] = [columns[0], {
    key: "related_object", path: "related.name", label: "Related object", kind: "text", link: "/app/entities/{related.id}",
  }];
  render(<DataTable caption="Synthetic computers" columns={computerTableColumns(linkedColumns, onSelect)} rows={[row]} rowKey={(item) => String(item.entity_id)} onRowClick={onSelect}/>);
  const link = screen.getByRole("link", { name: "synthetic-object" });
  const target = new URL(link.getAttribute("href")!, "http://example.test");
  expect(target.pathname).toBe("/app/entities/7");
  expect(target.searchParams.get("return_to")).toBe("/app/report/ad.computers.v6?domain_id=8&tab=checks");
  link.addEventListener("click", (event) => event.preventDefault(), { once: true });
  fireEvent.click(link);
  expect(onSelect).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "synthetic-host" }));
  expect(onSelect).toHaveBeenCalledExactlyOnceWith(row);
});

it("opens check deep links, preserves unknown counts and shows no warning for a fresh complete source", async () => {
  const { container } = show();
  await screen.findByText(check.title, { selector: "strong" });
  expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Требуют проверки", "Изменения", "Все компьютеры"]);
  expect(screen.getByRole("tab", { name: "Требуют проверки" }).getAttribute("aria-selected")).toBe("true");
  expect(container.querySelector(".sli-ds-review-list__item")?.hasAttribute("open")).toBe(false);
  expect(container.querySelector(".sli-ds-review-list__new")?.textContent).toBe("—");
  expect(container.querySelector(".sli-ds-review-list__total")?.textContent).toBe("4");
  expect(container.querySelectorAll('.sli-ds-callout[data-tone="warning"]')).toHaveLength(0);
  expect(requests).toHaveLength(1);
  expect(requests[0].get("tab")).toBe("checks");
  expect(screen.queryByText(/Нет компьютеров/)).toBeNull();
});

it.each(["ru", "en"] as const)("omits missing assessments and removes data commentary in %s", async (locale) => {
  setLocale(locale);
  respond = () => page({ items: [{ ...check, key: "missing", title: "Missing check", status: "not_evaluated", status_text: t("reports.ad.checks.status.not_evaluated"), total: null }, check],
    coverage: { not_evaluated_count: 50, observed_at_utc: "2026-11-13T12:00:00Z" },
    limitations: [{ code: "synthetic", text: "Synthetic removed limitation" }] });
  const { container } = show();
  await screen.findByText(check.title, { selector: "strong" });
  const summary = container.querySelector(".sli-ds-review-list__summary")!;
  expect(screen.queryByText("Missing check")).toBeNull();
  expect(summary.querySelector(".sli-ds-review-list__total")?.textContent).toBe("4");
  expect(summary.textContent).not.toContain("synthetic-preview");
  expect(container.querySelector(".sli-ds-review-list__heading")?.textContent).toBe([
    "severity", "title", "status_text", "new_count", "total",
  ].map((key) => t(`reports.ad.checks.column.${key}` as Parameters<typeof t>[0])).join(""));
  expect(container.textContent).not.toMatch(/Не оценено|Not evaluated|Компьютер может попадать|A computer may/);
  expect(container.textContent).not.toContain("Synthetic removed limitation");
  expect(screen.queryByText(t("reports.passport.more"))).toBeNull();
  expect(container.querySelectorAll(".sli-ds-state--banner, .sli-ds-callout")).toHaveLength(0);
  fireEvent.click(summary);
  expect(screen.getByRole("button", { name: "synthetic-preview" })).toBeTruthy();
});

it("keeps workspace navigation in the report tab strip", async () => {
  const onAdditionalTab = vi.fn();
  show({ additionalTabs: [{ key: "logons", label: "Входы на компьютеры" }], onAdditionalTab });
  await screen.findByText(check.title, { selector: "strong" });
  expect(screen.getAllByRole("tablist")).toHaveLength(1);
  expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual([
    "Требуют проверки", "Изменения", "Все компьютеры", "Входы на компьютеры",
  ]);
  fireEvent.click(screen.getByRole("tab", { name: "Входы на компьютеры" }));
  expect(onAdditionalTab).toHaveBeenCalledExactlyOnceWith("logons");
});

it("opens the right panel, expands it on demand, and returns to the split view on Escape", async () => {
  show();
  await screen.findByText(check.title, { selector: "strong" });
  fireEvent.click(screen.getByText(check.title, { selector: "strong" }).closest("summary")!);
  fireEvent.click(screen.getByRole("button", { name: "synthetic-preview" }));
  expect(screen.getByRole("complementary", { name: "synthetic-preview" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("reports.computers.expand") }));
  expect(screen.getByRole("dialog", { name: "synthetic-preview" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Требуют проверки" })).toBeTruthy();
  fireEvent.keyDown(document, { key: "Escape" });
  expect(screen.queryByRole("dialog")).toBeNull();
  fireEvent.click(screen.getByRole("tab", { name: "Все компьютеры" }));
  fireEvent.click(await screen.findByRole("button", { name: "synthetic-host" }));
  const drawer = screen.getByRole("complementary", { name: "synthetic-host" });
  expect(within(drawer).getByText("Контроллер домена")).toBeTruthy();
  expect(screen.getByRole("table", { name: "Все компьютеры" })).toBeTruthy();
  expect(screen.queryByRole("link", { name: "synthetic-host" })).toBeNull();
});

it("requests each tab in domain scope and exports changes, with role and compact mobile columns", async () => {
  show();
  await screen.findByText(check.title, { selector: "strong" });
  fireEvent.click(screen.getByRole("tab", { name: "Изменения" }));
  await screen.findByText("Synthetic discovery");
  const table = screen.getByRole("table", { name: "Изменения" });
  expect(within(table).getByText("Контроллер домена")).toBeTruthy();
  expect(table.getAttribute("data-responsive")).toBe("true");
  expect(within(table).getByText("Было").getAttribute("data-mobile")).toBe("false");
  expect(within(table).getByText("Роль").getAttribute("data-mobile")).toBe("true");
  const params = new URL(screen.getByRole("link", { name: "Экспорт CSV" }).getAttribute("href")!, "http://example.test").searchParams;
  expect(params.get("tab")).toBe("changes");
  expect(params.get("domain_id")).toBe("8");
  expect(requests.every((request) => (request.get("domain_id") ?? request.get("domain")) === "8")).toBe(true);
  fireEvent.click(screen.getByRole("tab", { name: "Все компьютеры" }));
  await screen.findByRole("button", { name: "synthetic-host" });
  expect(screen.queryByText("unknown")).toBeNull();
  expect(screen.queryByRole("columnheader", { name: "Windows LAPS" })).toBeNull();
});

it("retains cursor pagination on inventory and never shows another tab's rows", async () => {
  respond = (params) => params.get("tab") === "computers"
    ? page({ state: "ok", items: [{ ...host, entity_id: params.get("cursor") ? 2 : 1, display_name: params.get("cursor") ? "synthetic-next" : host.display_name }],
      has_more: !params.get("cursor"), next_cursor: params.get("cursor") ? null : "opaque" }) : page();
  show();
  await screen.findByText(check.title, { selector: "strong" });
  fireEvent.click(screen.getByRole("tab", { name: "Все компьютеры" }));
  await screen.findByRole("button", { name: "synthetic-host" });
  fireEvent.click(screen.getByRole("button", { name: t("table.next") }));
  await screen.findByRole("button", { name: "synthetic-next" });
  expect(requests.at(-1)?.get("cursor")).toBe("opaque");
  fireEvent.click(screen.getByRole("tab", { name: "Требуют проверки" }));
  await waitFor(() => expect(screen.queryByRole("button", { name: "synthetic-next" })).toBeNull());
});

it("keeps checks selected after URL persistence and restores tabs through browser history", async () => {
  const first = show();
  await screen.findByText(check.title, { selector: "strong" });
  expect(new URLSearchParams(window.location.search).get("tab")).toBe("checks");
  first.unmount();
  show();
  await screen.findByText(check.title, { selector: "strong" });
  fireEvent.click(screen.getByRole("tab", { name: "Изменения" }));
  await screen.findByText("Synthetic discovery");
  window.history.back();
  await waitFor(() => expect(screen.getByRole("tab", { name: "Требуют проверки" }).getAttribute("aria-selected")).toBe("true"));
});

it("shows an empty comparison without source warnings or a note", async () => {
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?tab=changes&domain_id=8");
  respond = () => page({ items: [], collections: { changes: [] }, coverage: { comparison_missing_domains: ["example.test"],
    domains: [{ domain_name: "example.test", state: "complete", observed_at_utc: new Date().toISOString() }] } });
  const { container } = show();
  const comparison = within(await screen.findByRole("tabpanel", { name: "Изменения" }));
  await comparison.findByRole("status");
  expect(container.querySelectorAll('.sli-ds-callout[data-tone="warning"]')).toHaveLength(0);
  expect(container.textContent).not.toContain("Synthetic computer changes note");
  expect(comparison.getAllByRole("status")).toHaveLength(1);
});


it("keeps zero counts distinct from missing assessments without commentary and collapses the hygiene tail", () => {
  const { rerender, container } = render(<ComputerChecks result={page({ coverage: { not_evaluated_count: 0 }, items: [{ ...check, total: 0, is_lower_bound: false }, { ...check, id: "low", key: "low", severity: "low", total: 0, is_lower_bound: false }] })} onSelect={vi.fn()} onInventory={vi.fn()}/>);
  expect(container.querySelector(".sli-ds-review-list__total")?.textContent).toBe("0");
  expect(container.querySelector("[role='status']")).toBeNull();
  expect(container.querySelector("details[open]")).toBeNull();
  rerender(<ComputerChecks result={page({ items: [{ ...check, total: null }] })} onSelect={vi.fn()} onInventory={vi.fn()}/>);
  expect(container.querySelector(".sli-ds-review-list__item")).toBeNull();
  expect(computerRole("unknown")).toBe("—");
});

it("defines identical computer view translations in both locales", () => {
  const keys = Object.keys(ru).filter((key) => key.startsWith("reports.ad.computers.") || key.startsWith("reports.v2.ad.computers.v6.views.changes."));
  expect(Object.keys(en).filter((key) => key.startsWith("reports.ad.computers.") || key.startsWith("reports.v2.ad.computers.v6.views.changes.")).sort()).toEqual(keys.sort());
  for (const key of keys) expect(en[key as keyof typeof en]).not.toMatch(/[А-Яа-яЁё]/);
});

it("shows server filter counts and reloads the inventory with the selected role", async () => {
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?domain_id=8");
  respond = (params) => page({ state: "ok", items: [{ ...host, display_name: params.has("type") ? "synthetic-matching-host" : host.display_name }],
    filter_options: { type: [{ value: "domain_controller", label: "Controller", count: 4 }] } });
  show();
  await chooseOption(await screen.findByLabelText("Тип", { selector: "button" }), "domain_controller");
  expect(screen.getByLabelText("Тип", { selector: "button" }).textContent).toContain("Контроллер домена (4)");
  await screen.findByRole("button", { name: "synthetic-matching-host" });
  expect(requests.at(-1)?.get("type")).toBe("domain_controller");
});

it("uses exact computer scope for card changes, problems, and source event links", async () => {
  const computer = { ...host, computer_type: "workstation", dns_host_name: "synthetic-host.example.test" };
  effective.reports = ["ad.computer-logons", "security.queue", "events.explorer"].map((report_key) => ({ report_key, allowed: true }));
  respond = (params) => params.has("object_guid")
    ? page({ state: "ok", items: [{ row_id: "event:1", change_type: "membership_added", group_name: "synthetic-group", source_event_id: 9 }] })
    : page({ state: "ok", items: [computer] });
  respondTo = (url) => {
    if (url.pathname.endsWith("/security.problems/data")) return page({ coverage: { open_by_severity: { critical: 2 } } });
    if (url.pathname.endsWith("/rows/1/detail")) return page({ items: [
      { source_event_id: 15, user_name: "synthetic-user", observed_at_utc: "2026-11-22T07:13:00Z" },
      { source_event_id: 14, user_name: "synthetic-user", observed_at_utc: "2026-11-22T07:12:00Z" },
    ], computer_logon_activity: { days: [], total: 2, typical: 2, top: { account: "synthetic-user", count: 2 } } });
  };
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?domain_id=8");
  show();
  const card = await screen.findByRole("complementary", { name: "synthetic-host" });
  const problems = (await within(card).findByText("Открытые проблемы")).parentElement!;
  const count = await within(problems).findByRole("link", { name: /Критическая 2/ });
  const target = new URL(count.getAttribute("href")!, "http://example.test");
  expect(target.pathname).toBe("/app/report/security.problems");
  expect(Object.fromEntries(target.searchParams)).toEqual({ domain: "8", entity_id: "1", population: "open" });
  expect(within(card).getByRole("link", { name: "Открыть журнал событий" }).getAttribute("href")).toContain("synthetic-host.example.test");
  fireEvent.click(within(card).getByRole("tab", { name: "Изменения" }));
  await within(card).findByText(/synthetic-group/);
  expect(requests.at(-1)?.get("object_guid")).toBe(host.object_guid);
  expect(within(card).getByRole("link", { name: "#9" }).getAttribute("href")).toContain("/app/events/9?");
  fireEvent.click(within(card).getByRole("tab", { name: "Входы" }));
  await within(card).findByText("synthetic-user (2 за период)");
  const table = within(card).getByRole("table", { name: "Наблюдения за период" });
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows).toHaveLength(2);
  expect(within(rows[0]).getByRole("cell", { name: formatDateTime("2026-11-22T07:13:00Z", DEFAULT_TIME_ZONE) })).toBeTruthy();
  expect(within(rows[1]).getByRole("cell", { name: formatDateTime("2026-11-22T07:12:00Z", DEFAULT_TIME_ZONE) })).toBeTruthy();
  expect(within(rows[0]).getByRole("link", { name: "#15" }).getAttribute("href")).toContain("/app/events/15?");
  expect(within(rows[1]).getByRole("link", { name: "#14" }).getAttribute("href")).toContain("/app/events/14?");
  expect(within(card).getByRole("link", { name: "Открыть событие" }).getAttribute("href")).toContain("/app/events/15?");
  fireEvent.click(rows[1]);
  expect(within(card).getByRole("link", { name: "Открыть событие" }).getAttribute("href")).toContain("/app/events/14?");
});

it("opens every open state for the computer and keeps the scope in the queue request", async () => {
  effective.reports = [{ report_key: "security.queue", allowed: true }];
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?domain_id=8");
  const finding = (id: number, status: string, title_text: string) => ({
    id, status, title_text, severity: "high", entity_text: "synthetic-host",
  });
  const related = [finding(21, "new", "Synthetic new"), finding(22, "active", "Synthetic active"), finding(23, "review", "Synthetic review")];
  respondTo = (url) => {
    if (url.pathname.endsWith("/security.problems/data")) {
      if (url.searchParams.get("limit") === "1") return page({ coverage: { open_by_severity: { high: 3 } } });
      const { searchParams: params } = url;
      const scoped = params.get("domain") === "8" && params.get("entity_id") === "1" && params.get("population") === "open";
      return page({ state: "ok", items: scoped ? related : [...related, finding(24, "closed", "Synthetic closed")] });
    }
    if (url.pathname.endsWith("/security.problems")) return {
      ...definition, key: "security.problems", title: "Проблемы", archetype: "queue", export: false, views: [],
      params: [{ key: "entity_id", kind: "text" }, { key: "population", kind: "choice" }, { key: "queue_view", kind: "choice" }],
    };
  };
  const computer = show();
  const card = await screen.findByRole("complementary", { name: "synthetic-host" });
  const link = await within(card).findByRole("link", { name: /Высокая 3/ });
  const target = new URL(link.getAttribute("href")!, "http://example.test");
  computer.unmount();
  show({ reportKey: "security.problems", initialSearch: target.search });
  for (const name of [/Synthetic new/, /Synthetic active/, /Synthetic review/])
    expect(await screen.findByRole("link", { name })).toBeTruthy();
  expect(screen.queryByRole("link", { name: /Synthetic closed/ })).toBeNull();
  const count = requests.find((params) => params.get("entity_id") === "1" && params.get("limit") === "1");
  const queue = requests.find((params) => params.get("entity_id") === "1" && params.get("limit") === "50");
  for (const params of [count, queue]) {
    expect(params?.get("domain")).toBe("8");
    expect(params?.get("population")).toBe("open");
    expect(params?.get("queue_view")).toBe("all");
  }
});

const logons: ReportDefinitionDto = { ...definition, key: "ad.computer-logons", title: "Входы на компьютеры", export: false,
  params: [{ key: "period", label: "Период", kind: "period", default: "30d", required: true },
    { key: "domain_id", label: "Домен", kind: "domain", hidden: true }, { key: "user", label: "Пользователь", kind: "text" },
    { key: "with_logons", label: "Только ПК со входами", kind: "choice", hidden: true },
    { key: "service_logons", label: "Сетевые и служебные входы", kind: "choice" }],
  views: [{ key: "table", kind: "table" }],
  row_key: "computer_key",
  columns: [{ key: "name", label: "Компьютер", kind: "text", path: "display_name" },
    { key: "count", label: "Входов за период", kind: "number", path: "login_count" },
    { key: "last", label: "Последний вход", kind: "datetime", path: "last_observed_logon_at_utc" }],
};

it("keeps the logon window and filters when paging and opening the next computer", async () => {
  const key = logons.key;
  const detail: URLSearchParams[] = [];
  respondTo = (url) => {
    if (url.pathname.endsWith(key)) return logons;
    const includesService = url.searchParams.get("service_logons") === "yes";
    if (url.pathname.endsWith("/detail")) {
      detail.push(url.searchParams);
      return page({ report_key: key, state: "ok", items: [
        { row_id: "20", source_event_id: 20, observed_at_utc: "2026-11-21T12:00:00Z", user_name: "synthetic-user", logon_type: "10", repeat_count: 1 },
        ...(includesService ? [{ row_id: "21", source_event_id: 21, user_name: "SYSTEM", logon_type: "5", repeat_count: 2 }] : []),
      ] });
    }
    if (url.pathname.endsWith("/data")) {
      const next = url.searchParams.has("cursor");
      return page({ report_key: key, state: "ok", items: [{ computer_key: next ? "host-8-bmV4dA" : "host-8-aG9zdA",
        computer_type: next ? "server" : "domain_controller", login_count: includesService ? 3 : 1,
        display_name: next ? "synthetic-next" : "synthetic-host" }], has_more: !next, next_cursor: next ? null : "opaque" });
    }
  };
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?nav_view=logons&domain_id=8&user=synthetic-user");
  show({ reportKey: key });
  await screen.findByRole("link", { name: "#20" });
  const serviceLogons = screen.getByRole<HTMLInputElement>("checkbox", { name: "Сетевые и служебные входы" });
  const computers = () => within(screen.getByRole("table", { name: "Входы на компьютеры" }));
  expect(computers().getByRole("img", { name: "Контроллер домена" })).toBeTruthy();
  expect(computers().getByRole("cell", { name: "1" })).toBeTruthy();
  expect(screen.queryByRole("link", { name: "#21" })).toBeNull();
  expect(serviceLogons.checked).toBe(false);
  expect(requests[0].get("service_logons")).not.toBe("yes");
  fireEvent.click(serviceLogons);
  await screen.findByRole("link", { name: "#21" });
  expect(computers().getByRole("cell", { name: "3" })).toBeTruthy();
  expect(detail.at(-1)?.get("service_logons")).toBe("yes");
  const detailCountBeforePaging = detail.length;
  const nextComputerPage = screen.getAllByRole<HTMLButtonElement>("button", { name: t("table.next") }).find((button) => !button.disabled)!;
  fireEvent.click(nextComputerPage);
  await screen.findByRole("complementary", { name: "synthetic-next" });
  expect(computers().getByRole("img", { name: "Сервер" })).toBeTruthy();
  expect(requests.at(-1)?.get("cursor")).toBe("opaque");
  expect(requests.at(-1)?.get("service_logons")).toBe("yes");
  await waitFor(() => expect(detail.length).toBeGreaterThan(detailCountBeforePaging));
  expect(detail.at(-1)?.get("service_logons")).toBe("yes");
  for (const params of [...requests, ...detail]) {
    expect(params.get("period")).toBe("custom");
    expect(params.get("from")).toBe(requests[0].get("from"));
    expect(params.get("to")).toBe(requests[0].get("to"));
    expect(params.get("user")).toBe("synthetic-user");
    expect(params.get("domain_id")).toBe("8");
  }
  fireEvent.click(serviceLogons);
  await waitFor(() => expect(computers().getByRole("cell", { name: "1" })).toBeTruthy());
  expect(screen.queryByRole("link", { name: "#21" })).toBeNull();
});

it("shows an empty logon table without requesting computer details", async () => {
  const details = vi.fn();
  respondTo = (url) => {
    if (url.pathname.endsWith(logons.key)) return logons;
    if (url.pathname.endsWith("/detail")) return details();
    if (url.pathname.endsWith("/data")) {
      return page({ report_key: logons.key, state: "empty", items: [], filtered_count: 0, coverage: {} });
    }
  };
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?nav_view=logons&domain_id=8&with_logons=yes");
  show({ reportKey: logons.key });
  const table = await screen.findByRole("table", { name: "Входы на компьютеры" });
  expect(within(table).getByText("За выбранный период записей нет.")).toBeTruthy();
  expect(screen.queryByRole("checkbox", { name: "Только ПК со входами" })).toBeNull();
  expect(details).not.toHaveBeenCalled();
});
