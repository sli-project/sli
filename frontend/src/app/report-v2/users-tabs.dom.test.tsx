// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ReportRenderer } from "./ReportRenderer";

const titles = { checks: "Требуют проверки", privileged: "Привилегированные", changes: "Изменения", all: "Все учётки", disabled_active: "Отключены, но активны" };
const visibleTitles = [titles.checks, titles.privileged, titles.all];
const definition: ReportDefinitionDto = {
  key: "ad.users.v2", section: "reports/identity", title: "Пользователи", description: "", archetype: "inventory-status",
  params: [{ key: "q", kind: "text", label: "Поиск" }, { key: "domain", kind: "domain", label: "Домен", hidden: true },
    { key: "account_rows", kind: "text", label: "Account rows", hidden: true },
    { key: "check", kind: "text", label: "Check", hidden: true },
    { key: "as_of", kind: "text", label: "Состав на дату", hidden: true },
    { key: "account_state", kind: "choice", label: "Состояние", options: [{ value: "disabled", label: "Отключена" }, { value: "unknown", label: "Нет данных" }] }],
  columns: [{ key: "name", label: "Пользователь", path: "display_name", kind: "text", link: "/app/entities/{entity_id}" },
    { key: "state", label: "Включена", path: "enabled", kind: "boolean" },
    { key: "activity", path: "activity_at", label: "Последняя активность", kind: "datetime" },
    { key: "reason", path: "reason_text", label: "Отклонение", kind: "text" },
    { key: "privilege_basis", label: "Основание привилегий", path: "privilege_basis", kind: "list" }],
  views: Object.entries(titles).map(([key, title]) => ({ key, title, kind: "table", source: key === "checks" || key === "changes" ? key : "items",
    ...(key === "changes" ? { columns: [{ key: "name", path: "display_name", label: "Пользователь", kind: "text" as const },
      { key: "change", path: "label", label: "Изменение", kind: "text" as const }] } : {}) })),
  row_key: "id", detail: "fields", export: true, limits: { default: 50, max: 500 }, presets: [], row_links: [], filter_options: {},
};
const calls: URLSearchParams[] = [];
const account = (id: number, name = `Synthetic account ${id}`) => ({ id, entity_id: id, domain_id: 8, display_name: name, sam: `synthetic-${id}`, enabled: true });
const mainReason = { key: "reversible_password", label: "Synthetic primary deviation", severity: "high" };
const otherReason = { key: "password_never_expires", label: "Synthetic secondary deviation", severity: "low" };
const reviewAccount = { ...account(1), severity: "high", review_reasons: [mainReason, otherReason] };
const checkOptions = [
  { value: mainReason.key, label: mainReason.label, count: 7 },
  { value: otherReason.key, label: otherReason.label, count: 1 },
  { value: "disabled_logon", label: "Вход отключённой учётки", count: 1 },
  { value: "zero", label: "Zero check", count: 0 },
];
function page(tab: string, overrides: Partial<ReportResultDto> = {}): ReportResultDto {
  return { contract_id: "sli.report-result.v2", report_key: definition.key, state: "ok",
    items: tab === "checks" ? [reviewAccount] : [account(1, `Synthetic ${tab}`)], filtered_count: 1,
    has_more: false, next_cursor: null, metrics: [], series: {},
    coverage: { population: 7, affected_objects: 7, not_evaluated_count: 2 }, filter_options: tab === "checks" ? { check: checkOptions } : {}, limitations: [], window: {},
    collections: tab === "changes" ? { changes: [{ ...account(1), label: "Synthetic change" }] } : {}, ...overrides };
}
function mock(response: (params: URLSearchParams) => Response | Promise<Response> = (params) => new Response(JSON.stringify(page(params.get("tab") ?? "checks"))), raw = definition) {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/security.problems/data?")) {
      const params = new URL(url, "http://example.test").searchParams;
      const counts = params.get("entity_id") === "1" && params.get("domain") === "8" && params.get("population") === "open"
        && params.get("queue_view") === "all" && params.get("limit") === "1" ? { high: 3, medium: 1 } : undefined;
      return new Response(JSON.stringify(page("all", { coverage: { open_by_severity: counts } })));
    }
    if (url.includes("/rows/1/detail?")) return new Response(JSON.stringify(page("all", { items: [{
      ...account(1, "Synthetic all"),
      direct_memberships: [{ id: "group:2", name: "Synthetic team" }],
      privilege_paths: [{
        groupId: "group:2", relation: "direct", nodes: [{ id: "user:1" }, { id: "group:2", name: "Synthetic team" }],
      }, { groupId: "group:3", relation: "nested",
        nodes: [{ id: "user:1", name: "synthetic-1" }, { id: "group:2", name: "Synthetic team" }, { id: "group:3", name: "Synthetic admins" }] }],
      timeline: [
        { id: 1, event_id: 4625, at_utc: "2026-11-20T11:57:00Z", first_seen_utc: "2026-11-20T11:57:00Z", event_count: 1, actor: "synthetic-1" },
        { id: 2, event_id: 4625, at_utc: "2026-11-20T11:51:00Z", first_seen_utc: "2026-11-20T11:51:00Z", event_count: 1, actor: "synthetic-1" },
        { id: 3, event_id: 4728, at_utc: "2026-11-19T11:00:00Z", actor: "synthetic-admin", member: "synthetic-1", target: "Synthetic team" },
      ],
      changes: [{ id: 3, event_id: 4728, at_utc: "2026-11-19T11:00:00Z", actor: "synthetic-admin", member: "synthetic-1", target: "Synthetic team" }],
      computers: [{ computer: "test-ws", at_utc: "2026-11-18T11:00:00Z" }],
    }] })));
    if (url.includes("/rows/2/detail?")) return new Response(JSON.stringify(page("all", { items: [{
      ...account(2),
      direct_memberships: [{ id: "group:2", name: "Synthetic team" }],
      privilege_paths: [{ groupId: "group:2", relation: "direct", nodes: [{ id: "user:2" }, { id: "group:2", name: "Synthetic team" }] }],
    }] })));
    if (!url.includes("/data?")) return new Response(JSON.stringify(raw));
    const params = new URL(url, "http://example.test").searchParams;
    calls.push(params); return response(params);
  }));
}
function show() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ReportRenderer reportKey={definition.key}/></QueryClientProvider>);
}
beforeEach(() => {
  calls.length = 0;
  window.history.replaceState(null, "", "/app/report/ad.users.v2");
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru"); mock();
});
afterEach(() => { cleanup(); setLocale("ru"); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it("starts with account rows, filters by nonempty checks, and opens the filtered account", async () => {
  mock((params) => new Response(JSON.stringify(page("checks", params.has("check")
    ? { items: [{ ...account(2), review_reasons: [otherReason] }] } : {}))));
  show();
  const table = await screen.findByRole("table", { name: titles.checks });
  const row = within(table).getByRole("row", { name: /synthetic-1/ });
  expect(within(row).getByText(mainReason.label)).toBeTruthy();
  expect(within(row).queryByText(otherReason.label)).toBeNull();
  const more = within(row).getByRole("button", { name: t("reports.ad.users.list.more_deviations", { count: 1 }) });
  fireEvent.click(more);
  const unfilteredCard = within(await screen.findByRole("dialog"));
  expect(unfilteredCard.getByText(otherReason.label)).toBeTruthy();
  fireEvent.click(unfilteredCard.getByRole("button", { name: t("drawer.close") }));
  expect(screen.queryByRole("button", { name: /Zero check/ })).toBeNull();
  expect(calls[0].get("account_rows")).toBe("yes");
  fireEvent.click(screen.getByRole("button", { name: new RegExp(otherReason.label) }));
  const filtered = await screen.findByRole("row", { name: /synthetic-2/ });
  expect(screen.queryByRole("row", { name: /synthetic-1/ })).toBeNull();
  expect(new URLSearchParams(window.location.search).get("check")).toBe(otherReason.key);
  fireEvent.click(filtered);
  const card = within(await screen.findByRole("dialog"));
  expect(card.getByRole("heading", { name: "Synthetic account 2" })).toBeTruthy();
  expect(card.getByText(otherReason.label)).toBeTruthy();
  expect(calls.some((params) => params.get("limit") === "1")).toBe(false);
});

it.each([
  ["en", /^Data as of .*21.*2026/],
  ["ru", /^Данные на .*21.*2026/],
] as const)("shows the collection time in the Users header in %s", async (locale, label) => {
  setLocale(locale);
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all&domain=8");
  mock(() => Response.json(page("all", { coverage: { observed_at_utc: "2026-11-21T12:00:00Z" } })));
  show();
  expect(await screen.findByText(label)).toBeTruthy();
});

it("preserves an enabled or disabled filter without offering unknown status", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all");
  show();
  await screen.findByRole("table");
  const filter = screen.getByLabelText(t("reports.v2.ad.users.v2.params.account_state.label"), { selector: "button" });
  await userEvent.click(filter);
  const options = await screen.findAllByRole("option");
  expect(options.map((option) => option.dataset.key)).not.toContain("unknown");
  await userEvent.click(options.find((option) => option.dataset.key === "disabled")!);
  await waitFor(() => expect(calls.some((params) => params.get("account_state") === "disabled")).toBe(true));
});

it("opens the right panel from a name and restores focus without losing the list", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all"); show();
  const button = await screen.findByRole("button", { name: "synthetic-1" }); button.focus(); fireEvent.click(button);
  const dialog = await screen.findByRole("dialog");
  expect(document.activeElement).toBe(dialog);
  const tabPanel = screen.getByRole("tabpanel", { name: /Все учётки/ });
  expect(within(tabPanel).getByRole("table", { name: "Все учётки" })).toBeTruthy();
  expect(screen.queryByRole("link", { name: "Synthetic all" })).toBeNull();
  fireEvent.keyDown(dialog, { key: "Escape" }); expect(screen.queryByRole("dialog")).toBeNull();
  expect(document.activeElement).toBe(button);
});

it("shows nested privilege paths and links to account-scoped reports", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all&domain=8"); show();
  fireEvent.click(await screen.findByRole("button", { name: "synthetic-1" }));
  const card = within(await screen.findByRole("dialog"));
  expect(await card.findByRole("heading", { name: "Компьютеры за 30 дней" })).toBeTruthy();
  const problems = new URL((await card.findByRole("link", { name: "Открытые проблемы: 4 →" })).getAttribute("href")!, window.location.origin);
  expect(problems.pathname).toBe("/app/report/security.problems");
  expect(Object.fromEntries(problems.searchParams)).toMatchObject({ entity_id: "1", domain: "8", population: "open" });
  const changes = new URL(card.getByRole("link", { name: "Изменения объекта →" }).getAttribute("href")!, window.location.origin);
  expect(changes.pathname).toBe("/app/report/security.events.chains");
  expect(Object.fromEntries(changes.searchParams)).toMatchObject({ entity_id: "1", domain: "8", return_to: expect.stringContaining("tab=all") });
  expect(card.queryByRole("tab", { name: "Изменения" })).toBeNull();
  fireEvent.click(card.getByRole("tab", { name: "Права" }));
  expect(card.getAllByRole("list").at(-1)?.querySelectorAll("li")).toHaveLength(3);
  expect(card.getByRole("link", { name: "Synthetic admins" }).getAttribute("href")).toContain("/app/entities/3");
  fireEvent.click(card.getByRole("tab", { name: "Активность" }));
  expect(card.getByText(/Отказ во входе · synthetic-1 ×2/)).toBeTruthy();
  expect(card.queryByText(/Добавление в группу/)).toBeNull();
  fireEvent.click(card.getByRole("checkbox", { name: "Свернуть повторы" }));
  expect(card.queryByText(/×2/)).toBeNull();
  expect(card.getByRole("link", { name: "События пользователя" }).getAttribute("href")).toContain("/app/report/events.journal?q=synthetic-1");
});

it("pages fifty at a time, supports back and resets after filtering", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all&domain=8");
  mock((params) => new Response(JSON.stringify(page("all", params.get("cursor") === "50"
    ? { items: [account(51)], filtered_count: 51 }
    : { items: Array.from({ length: 50 }, (_, i) => account(i + 1)), filtered_count: 51, has_more: true, next_cursor: "50" }))));
  show(); expect(await screen.findByText("Страница 1 из 2")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Вперёд" })); expect(await screen.findByText("Страница 2 из 2")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "synthetic-1" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Назад" })); expect(await screen.findByText("Страница 1 из 2")).toBeTruthy();
  expect(calls.every((params) => params.get("domain") === "8")).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "Вперёд" })); await screen.findByText("Страница 2 из 2");
  fireEvent.change(screen.getByLabelText("Поиск"), { target: { value: "synthetic" } }); fireEvent.submit(screen.getByLabelText("Поиск").closest("form")!);
  expect(await screen.findByText("Страница 1 из 2")).toBeTruthy();
});

it("requests composition on a date and preserves that date in CSV", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=privileged&domain=8"); show();
  await screen.findByRole("table", { name: "Привилегированные" });
  fireEvent.change(screen.getByLabelText("Состав на дату"), { target: { value: "2026-10-17" } });
  await waitFor(() => expect(calls.some((params) => params.get("as_of") === "2026-10-17")).toBe(true));
  expect(screen.getByRole("link", { name: "Экспорт CSV" }).getAttribute("href")).toContain("as_of=2026-10-17");
});

it("uses account units on server counts and keeps disabled logons in the review filters", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all&domain=8");
  mock((params) => new Response(JSON.stringify(params.get("tab") === "checks"
    ? page("checks", params.get("check") === "disabled_logon" ? { items: [account(2)] } : {})
    : page("all", { coverage: { privileged_accounts: 2 }, filtered_count: 12 }))));
  show();
  expect(await screen.findByRole("tab", { name: "Все учётки 12 учётных записей" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Привилегированные 2 учётные записи" })).toBeTruthy();
  expect(screen.queryByRole("tab", { name: titles.disabled_active })).toBeNull();
  expect(screen.queryByRole("tab", { name: titles.changes })).toBeNull();
  fireEvent.click(screen.getByRole("tab", { name: titles.checks }));
  expect(await screen.findByRole("tab", { name: "Требуют проверки 7 учётных записей" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Вход отключённой учётки 1" }));
  await screen.findByRole("button", { name: "synthetic-2" });
  expect(calls.some((params) => params.get("tab") === "checks" && params.get("check") === "disabled_logon")).toBe(true);
  fireEvent.click(within(screen.getByRole("radiogroup", { name: "Строк на странице" })).getByRole("radio", { name: "25" }));
  await waitFor(() => expect(calls.some((params) => params.get("tab") === "checks" && params.get("limit") === "25")).toBe(true));
});

it("shows direct memberships without a duplicate privilege path", async () => {
  mock(() => new Response(JSON.stringify(page("checks", { items: [account(2)] }))));
  show();
  fireEvent.click(await screen.findByRole("button", { name: "synthetic-2" }));
  const card = within(await screen.findByRole("dialog"));
  expect(card.queryByRole("link", { name: /Открытые проблемы: 0/ })).toBeNull();
  fireEvent.click(card.getByRole("tab", { name: "Права" }));
  expect(await card.findByRole("link", { name: "Synthetic team" })).toBeTruthy();
  expect(card.queryByRole("heading", { name: "Путь привилегии" })).toBeNull();
});

it.each(["active", "disabled", "risk", "semantic"])("normalizes legacy %s links", async (legacy) => {
  window.history.replaceState(null, "", `/app/report/ad.users.v2?tab=${legacy}&q=synthetic`); show();
  await waitFor(() => expect(calls.length).toBeGreaterThan(0)); expect(calls.some((params) => params.get("tab") === legacy)).toBe(false);
  expect(screen.getAllByRole("tab").map((tab) => tab.textContent?.replace(/ \d+ учётн.*$/, ""))).toEqual(visibleTitles); expect(new URLSearchParams(window.location.search).get("q")).toBe("synthetic");
});

it("keeps denied tabs visible without querying or exporting them", async () => {
  mock(undefined, { ...definition, views: definition.views.map((view) => view.key === "privileged" ? { ...view, access: { allowed: false } } : view) });
  show(); await screen.findByRole("table", { name: titles.checks }); fireEvent.click(screen.getByRole("tab", { name: "Привилегированные" }));
  expect(within(await screen.findByRole("alert")).getByText("Нет доступа")).toBeTruthy();
  expect(screen.queryByRole("link", { name: "Экспорт CSV" })).toBeNull(); expect(calls.some((params) => params.get("tab") === "privileged")).toBe(false);
});

it.each(["ru", "en"] as const)("shows partial results without source warnings or invented totals (%s)", async (locale) => {
  setLocale(locale); mock(() => new Response(JSON.stringify(page("checks", { state: "partial", coverage: { not_evaluated_count: null,
    domains: [{ domain_id: 8, domain_name: "example.test", state: "complete", observed_at_utc: "2020-01-01T00:00:00Z" }] },
    state_details: { reason: "freshness_exceeded", source: "dc01.example.test", stale_since_utc: "2020-01-01T00:00:00Z" },
  }))));
  const { container } = show(); await screen.findByRole("table", { name: t("reports.v2.ad.users.v2.views.checks.title") });
  expect(screen.queryByRole("status")).toBeNull();
  expect(container.querySelector(".sli-ds-state--banner")).toBeNull();
  expect(screen.getByRole("button", { name: "synthetic-1" })).toBeTruthy();
  expect(screen.queryByText(/(?:Не оценено|Not evaluated): 0/)).toBeNull();
  expect(screen.queryByText("Полнота не подтверждена")).toBeNull();
});

it("submits search once, preserves its URL and clears it without an apply button", async () => {
  show(); await screen.findByRole("table", { name: titles.checks });
  const search = screen.getByRole("searchbox", { name: "Поиск" });
  fireEvent.change(search, { target: { value: "synthetic" } });
  expect(calls.some((params) => params.has("q"))).toBe(false);
  fireEvent.submit(search.closest("form")!);
  await waitFor(() => expect(calls.some((params) => params.get("q") === "synthetic")).toBe(true));
  expect(new URLSearchParams(window.location.search).get("q")).toBe("synthetic");
  fireEvent.change(search, { target: { value: "" } });
  await waitFor(() => expect(new URLSearchParams(window.location.search).has("q")).toBe(false));
});

it.each(["users", "temporary_memberships", "changes", "disabled_active"])("reduces the server tabs and normalizes the removed %s link", async (tab) => {
  window.history.replaceState(null, "", `/app/report/ad.users.v2?tab=${tab}&domain=8`);
  mock(undefined, { ...definition, views: [...definition.views,
    { key: "users", title: "Пользователи", kind: "table", source: "items" },
    { key: "temporary_memberships", title: "Краткое членство в контрольных группах", kind: "table", source: "temporary_memberships" },
  ] });
  show(); await waitFor(() => expect(calls.length).toBeGreaterThan(0));
  expect(screen.getAllByRole("tab").map((item) => item.textContent?.replace(/ \d+ учётн.*$/, ""))).toEqual(visibleTitles);
  expect(calls.every((params) => params.get("tab") === (tab === "users" ? "all" : "checks") && params.get("domain") === "8")).toBe(true);
});
