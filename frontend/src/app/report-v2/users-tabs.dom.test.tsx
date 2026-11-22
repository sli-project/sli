// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ReportRenderer } from "./ReportRenderer";

const titles = { checks: "Требуют проверки", privileged: "Привилегированные", changes: "Изменения", all: "Все учётки", disabled_active: "Отключены, но активны" };
const definition: ReportDefinitionDto = {
  key: "ad.users.v2", section: "reports/identity", title: "Пользователи", description: "", archetype: "inventory-status",
  params: [{ key: "q", kind: "text", label: "Поиск" }, { key: "domain", kind: "domain", label: "Домен", hidden: true },
    { key: "as_of", kind: "text", label: "Состав на дату", hidden: true },
    { key: "account_state", kind: "choice", label: "Состояние", options: [{ value: "disabled", label: "Отключена" }] }],
  columns: [{ key: "name", label: "Пользователь", path: "display_name", kind: "text", link: "/app/entities/{entity_id}" },
    { key: "state", label: "Включена", path: "enabled", kind: "boolean" },
    { key: "privilege_basis", label: "Основание привилегий", path: "privilege_basis", kind: "list" }],
  views: Object.entries(titles).map(([key, title]) => ({ key, title, kind: "table", source: key === "checks" || key === "changes" ? key : "items",
    ...(key === "changes" ? { columns: [{ key: "name", path: "display_name", label: "Пользователь", kind: "text" as const },
      { key: "change", path: "label", label: "Изменение", kind: "text" as const }] } : {}) })),
  row_key: "id", detail: "fields", export: true, limits: { default: 50, max: 500 }, presets: [], row_links: [], filter_options: {},
};
const calls: URLSearchParams[] = [];
const account = (id: number, name = `Synthetic account ${id}`) => ({ id, entity_id: id, domain_id: 8, display_name: name, sam: `synthetic-${id}`, enabled: true });
const check = { id: "users:reversible_password", key: "reversible_password", title: "Synthetic check", severity: "high", severity_text: "Высокая",
  status: "not_evaluated", status_text: "Не оценено", total: 7, new_count: null, objects: [1, 2, 3].map((id) => ({ ...account(id), name: `synthetic-${id}`, domain_id: 8, domain_name: "example.test" })),
  remaining_objects: 4, why: "Synthetic why", action: "Synthetic action", remediation: "Synthetic remediation" };
function page(tab: string, overrides: Partial<ReportResultDto> = {}): ReportResultDto {
  return { contract_id: "sli.report-result.v2", report_key: definition.key, state: "ok",
    items: tab === "checks" ? [check] : [account(1, `Synthetic ${tab}`)], filtered_count: 1,
    has_more: false, next_cursor: null, metrics: [], series: {},
    coverage: { population: 7, affected_objects: 7, not_evaluated_count: 2 }, filter_options: {}, limitations: [], window: {},
    collections: tab === "changes" ? { changes: [{ ...account(1), label: "Synthetic change" }] } : {}, ...overrides };
}
function mock(response: (params: URLSearchParams) => Response | Promise<Response> = (params) => new Response(JSON.stringify(page(params.get("tab") ?? "checks"))), raw = definition) {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/rows/1/detail?")) return new Response(JSON.stringify(page("all", { items: [{
      ...account(1, "Synthetic all"),
      direct_memberships: [{ id: "group:2", name: "Synthetic team" }],
      privilege_paths: [{ groupId: "group:3", relation: "nested",
        nodes: [{ id: "user:1", name: "synthetic-1" }, { id: "group:2", name: "Synthetic team" }, { id: "group:3", name: "Synthetic admins" }] }],
      timeline: [
        { id: 1, event_id: 4625, at_utc: "2026-11-20T11:57:00Z", first_seen_utc: "2026-11-20T11:57:00Z", event_count: 1, actor: "synthetic-1" },
        { id: 2, event_id: 4625, at_utc: "2026-11-20T11:51:00Z", first_seen_utc: "2026-11-20T11:51:00Z", event_count: 1, actor: "synthetic-1" },
        { id: 3, event_id: 4728, at_utc: "2026-11-19T11:00:00Z", actor: "synthetic-admin", member: "synthetic-1", target: "Synthetic team" },
      ],
      changes: [{ id: 3, event_id: 4728, at_utc: "2026-11-19T11:00:00Z", actor: "synthetic-admin", member: "synthetic-1", target: "Synthetic team" }],
      computers: [{ computer: "test-ws", at_utc: "2026-11-18T11:00:00Z" }],
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

it("defaults to checks and shows the affected account count without counter queries", async () => {
  const { container } = show(); await screen.findByText("Synthetic check", { selector: "strong" });
  expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual([titles.checks + " 7", ...Object.values(titles).slice(1)]);
  expect(new URLSearchParams(window.location.search).get("tab")).toBe("checks");
  expect(screen.queryByText(/Не оценено|Нет сравнения|Одна учётка|≥/)).toBeNull();
  expect(container.querySelector(".sli-ds-review-list__objects")).toBeNull();
  expect(screen.queryByRole("button", { name: "Применить" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Сбросить" })).toBeNull();
  expect(screen.queryByText("Полнота не подтверждена")).toBeNull();
  expect(calls.some((params) => params.get("limit") === "1")).toBe(false);
});

it("uses the check view projection when inventory job-title access is absent", async () => {
  mock(() => new Response(JSON.stringify(page("checks", { items: [{ ...check, title: undefined }], collections: { checks: [check, { section: "not_evaluated" }] } }))));
  show(); expect(await screen.findByText("Synthetic check", { selector: "strong" })).toBeTruthy();
});

it("expands a check and opens every exact match with a bounded request", async () => {
  mock((params) => new Response(JSON.stringify(params.has("check")
    ? page("all", { items: Array.from({ length: 7 }, (_, i) => ({ ...account(i + 1), name: `synthetic-${i + 1}` })), filtered_count: 7 }) : page("checks"))));
  show(); fireEvent.click((await screen.findByText("Synthetic check", { selector: "strong" })).closest("summary")!);
  expect(await screen.findByText("Synthetic why")).toBeTruthy();
  expect(screen.getByText("Показаны 3 из 7")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Открыть все" }));
  expect(await screen.findByRole("button", { name: "synthetic-7" })).toBeTruthy();
  const request = calls.find((params) => params.has("check"))!;
  expect(request.get("check")).toBe("reversible_password"); expect(request.get("limit")).toBe("50");
});

it("opens the right panel from a name and restores focus without losing the list", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all"); show();
  const button = await screen.findByRole("button", { name: "synthetic-1" }); button.focus(); fireEvent.click(button);
  expect(await screen.findByRole("dialog")).toBeTruthy();
  expect(screen.getByRole("table", { name: "Все учётки" })).toBeTruthy();
  expect(screen.queryByRole("link", { name: "Synthetic all" })).toBeNull();
  fireEvent.keyDown(document, { key: "Escape" }); expect(screen.queryByRole("dialog")).toBeNull();
  expect(document.activeElement).toBe(button);
});

it("shows group paths, combined activity, and account-scoped Problems and journal links", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all&domain=8"); show();
  fireEvent.click(await screen.findByRole("button", { name: "synthetic-1" }));
  const card = within(await screen.findByRole("dialog"));
  expect(await card.findByRole("heading", { name: "Компьютеры за 30 дней" })).toBeTruthy();
  fireEvent.click(card.getByRole("tab", { name: "Права" }));
  expect(card.getByRole("link", { name: "Synthetic admins" }).getAttribute("href")).toContain("/app/entities/3");
  fireEvent.click(card.getByRole("tab", { name: "Активность" }));
  expect(card.getByText(/Отказ во входе · synthetic-1 ×2/)).toBeTruthy();
  expect(card.getByText(/Добавление в группу · synthetic-1 · Synthetic team · synthetic-admin/)).toBeTruthy();
  fireEvent.click(card.getByRole("checkbox", { name: "Свернуть повторы" }));
  expect(card.queryByText(/×2/)).toBeNull();
  fireEvent.click(card.getByRole("tab", { name: "Изменения" }));
  expect(card.queryByText(/Отказ во входе/)).toBeNull();
  expect(card.getByText(/Добавление в группу · synthetic-1 · Synthetic team · synthetic-admin/)).toBeTruthy();
  expect(card.getByRole("link", { name: "Связанные проблемы" }).getAttribute("href")).toContain("entity_id=1&domain=8");
  expect(card.getByRole("link", { name: "События пользователя" }).getAttribute("href")).toContain("/app/report/events.journal?q=synthetic-1");
});

it("pages fifty at a time, supports back and resets after filtering", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all&domain=8");
  mock((params) => new Response(JSON.stringify(page("all", params.get("cursor") === "50"
    ? { items: [account(51)], filtered_count: 51 }
    : { items: Array.from({ length: 50 }, (_, i) => account(i + 1)), filtered_count: 51, has_more: true, next_cursor: "50" }))));
  show(); expect(await screen.findByText("1–50 из 51")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Вперёд" })); expect(await screen.findByText("51–51 из 51")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "synthetic-1" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Назад" })); expect(await screen.findByText("1–50 из 51")).toBeTruthy();
  expect(calls.every((params) => params.get("domain") === "8")).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "Вперёд" })); await screen.findByText("51–51 из 51");
  fireEvent.change(screen.getByLabelText("Поиск"), { target: { value: "synthetic" } }); fireEvent.submit(screen.getByLabelText("Поиск").closest("form")!);
  expect(await screen.findByText("1–50 из 51")).toBeTruthy();
});

it("requests composition on a date and preserves that date in CSV", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=privileged&domain=8"); show();
  await screen.findByRole("table", { name: "Привилегированные" });
  fireEvent.change(screen.getByLabelText("Состав на дату"), { target: { value: "2026-10-17" } });
  await waitFor(() => expect(calls.some((params) => params.get("as_of") === "2026-10-17")).toBe(true));
  expect(screen.getByRole("link", { name: "Экспорт CSV" }).getAttribute("href")).toContain("as_of=2026-10-17");
});

it("uses server counts and changes page size on the disabled-active list", async () => {
  window.history.replaceState(null, "", "/app/report/ad.users.v2?tab=all&domain=8");
  mock((params) => {
    const tab = params.get("tab") ?? "all";
    return new Response(JSON.stringify(tab === "disabled_active" ? page(tab, { items: [], filtered_count: 1,
      collections: { disabled_active: [{ ...account(3), enabled: false }] } })
      : page(tab, { coverage: { privileged_accounts: 2 }, filtered_count: 12 })));
  }, { ...definition, views: definition.views.map((view) => view.key === "disabled_active"
    ? { ...view, source: "disabled_active", columns: [definition.columns[0]] } : view) });
  show();
  expect(await screen.findByRole("tab", { name: "Все учётки 12" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Привилегированные 2" })).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: titles.disabled_active }));
  expect(await screen.findByRole("tab", { name: "Отключены, но активны 1" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "synthetic-3" })).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Строк на странице"), { target: { value: "25" } });
  await waitFor(() => expect(calls.some((params) => params.get("tab") === "disabled_active" && params.get("limit") === "25")).toBe(true));
});

it("renders changes and restores tabs through browser history", async () => {
  show(); await screen.findByText("Synthetic check", { selector: "strong" }); fireEvent.click(screen.getByRole("tab", { name: "Изменения" }));
  expect(await screen.findByText("Synthetic change")).toBeTruthy(); window.history.back();
  await waitFor(() => expect(screen.getByRole("tab", { name: /^Требуют проверки/ }).getAttribute("aria-selected")).toBe("true"));
});

it.each(["active", "disabled", "risk", "semantic"])("normalizes legacy %s links", async (legacy) => {
  window.history.replaceState(null, "", `/app/report/ad.users.v2?tab=${legacy}&q=synthetic`); show();
  await waitFor(() => expect(calls.length).toBeGreaterThan(0)); expect(calls.some((params) => params.get("tab") === legacy)).toBe(false);
  expect(screen.getAllByRole("tab").map((tab) => tab.textContent?.replace(/ \d+$/, ""))).toEqual(Object.values(titles)); expect(new URLSearchParams(window.location.search).get("q")).toBe("synthetic");
});

it("keeps denied tabs visible without querying or exporting them", async () => {
  mock(undefined, { ...definition, views: definition.views.map((view) => view.key === "privileged" ? { ...view, access: { allowed: false } } : view) });
  show(); await screen.findByText("Synthetic check", { selector: "strong" }); fireEvent.click(screen.getByRole("tab", { name: "Привилегированные" }));
  expect(within(await screen.findByRole("alert")).getByText("Нет доступа")).toBeTruthy();
  expect(screen.queryByRole("link", { name: "Экспорт CSV" })).toBeNull(); expect(calls.some((params) => params.get("tab") === "privileged")).toBe(false);
});

it.each(["ru", "en"] as const)("shows partial results without source warnings or invented totals (%s)", async (locale) => {
  setLocale(locale); mock(() => new Response(JSON.stringify(page("checks", { state: "partial", coverage: { not_evaluated_count: null,
    domains: [{ domain_id: 8, domain_name: "example.test", state: "complete", observed_at_utc: "2020-01-01T00:00:00Z" }] },
    state_details: { reason: "freshness_exceeded", source: "dc01.example.test", stale_since_utc: "2020-01-01T00:00:00Z" },
  }))));
  const { container } = show(); await screen.findByText("Synthetic check", { selector: "strong" });
  expect(screen.queryByRole("status")).toBeNull();
  expect(container.querySelector(".sli-ds-state--banner")).toBeNull();
  expect(screen.queryByRole("button", { name: "synthetic-1" })).toBeNull();
  expect(screen.queryByText(/(?:Не оценено|Not evaluated): 0/)).toBeNull();
  expect(screen.queryByText("Полнота не подтверждена")).toBeNull();
});

it.each(["ru", "en"] as const)("keeps check columns, omits empty results and retains real zero counts (%s)", async (locale) => {
  setLocale(locale);
  const rows = [
    { ...check, key: "comparison", status: "no_comparison", status_text: "Нет сравнения с прошлым снимком", total: 0, is_lower_bound: true },
    { ...check, key: "unknown", total: null },
    { ...check, key: "zero", severity: "low", title: "Zero check", status: "unchanged", status_text: "Stable", total: 0, new_count: 0 },
  ];
  mock(() => new Response(JSON.stringify(page("checks", { items: rows }))));
  const { container } = show(); await screen.findByText("Zero check", { selector: "strong" });
  expect([...container.querySelectorAll(".sli-ds-review-list__heading > span")].map((cell) => cell.textContent)).toEqual([
    t("reports.ad.checks.column.severity"), t("reports.ad.checks.column.title"), t("reports.ad.checks.column.status_text"),
    t("reports.ad.checks.column.new_count"), t("reports.ad.checks.column.total"),
  ]);
  const summaries = [...container.querySelectorAll(".sli-ds-review-list__summary")];
  expect(summaries).toHaveLength(2);
  expect(summaries[0].querySelector(".sli-ds-review-list__status")?.textContent).toBe(locale === "ru" ? "Первая проверка" : "First check");
  expect(summaries[0].querySelector(".sli-ds-review-list__new")?.textContent).toBe("—");
  expect(summaries[0].querySelector(".sli-ds-review-list__total")?.textContent).toBe("0");
  expect(summaries[1].querySelector(".sli-ds-review-list__total")?.textContent).toBe("0");
  expect(container.textContent).not.toMatch(/Нет сравнения|No comparison|≥/);
  expect(screen.queryByText(/Одна учётка|An account may|Не оценено:|Not evaluated:/)).toBeNull();
  expect(screen.queryByRole("button", { name: "synthetic-1" })).toBeNull();
  fireEvent.click(summaries[0]);
  expect(await within(summaries[0].closest("details")!).findByRole("button", { name: "synthetic-1" })).toBeTruthy();
});

it("submits search once, preserves its URL and clears it without an apply button", async () => {
  show(); await screen.findByText("Synthetic check", { selector: "strong" });
  const search = screen.getByRole("searchbox", { name: "Поиск" });
  fireEvent.change(search, { target: { value: "synthetic" } });
  expect(calls.some((params) => params.has("q"))).toBe(false);
  fireEvent.submit(search.closest("form")!);
  await waitFor(() => expect(calls.some((params) => params.get("q") === "synthetic")).toBe(true));
  expect(new URLSearchParams(window.location.search).get("q")).toBe("synthetic");
  fireEvent.change(search, { target: { value: "" } });
  await waitFor(() => expect(new URLSearchParams(window.location.search).has("q")).toBe(false));
});

it.each(["users", "temporary_memberships"])("reduces the server tabs and normalizes the removed %s link", async (tab) => {
  window.history.replaceState(null, "", `/app/report/ad.users.v2?tab=${tab}&domain=8`);
  mock(undefined, { ...definition, views: [...definition.views,
    { key: "users", title: "Пользователи", kind: "table", source: "items" },
    { key: "temporary_memberships", title: "Краткое членство в контрольных группах", kind: "table", source: "temporary_memberships" },
  ] });
  show(); await waitFor(() => expect(calls.length).toBeGreaterThan(0));
  expect(screen.getAllByRole("tab").map((item) => item.textContent?.replace(/ \d+$/, ""))).toEqual(Object.values(titles));
  expect(calls.every((params) => params.get("tab") === (tab === "users" ? "all" : "checks") && params.get("domain") === "8")).toBe(true);
});
