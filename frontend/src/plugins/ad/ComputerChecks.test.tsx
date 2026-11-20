// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { ReportRenderer } from "../../app/report-v2/ReportRenderer";
import { ComputerChecks, computerRole, computerTableColumns } from "./ComputerChecks";
import { DataTable } from "../../design-system";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";

const columns: ReportDefinitionDto["columns"] = [
  { key: "display_name", path: "display_name", label: "Компьютер", kind: "text", link: "/app/entities/{entity_id}" },
  { key: "computer_type", path: "computer_type", label: "Тип", kind: "state", labels: { server: "Сервер", domain_controller: "Контроллер домена" } },
  { key: "operating_system", path: "operating_system", label: "ОС", kind: "text" },
  { key: "laps_state", path: "laps_state", label: "LAPS", kind: "state", hidden_by_default: true },
];
const definition: ReportDefinitionDto = {
  key: "ad.computers.v6", title: "Компьютеры", description: "", section: "reports/computers", archetype: "inventory-status",
  params: [{ key: "view", label: "Срез", kind: "choice", hidden: true, default: "all" },
    { key: "domain_id", label: "Домен", kind: "domain", hidden: true }, { key: "q", label: "Поиск", kind: "text" }],
  columns, views: [{ key: "checks", title: "Требуют проверки", kind: "table", source: "checks" },
    { key: "changes", title: "Изменения", kind: "table", source: "changes", note: "Synthetic computer changes note", columns: [...columns.slice(0, 2),
      { key: "change_type", path: "change_type", label: "Изменение", kind: "text" },
      { key: "before", path: "before", label: "Было", kind: "text" }, { key: "after", path: "after", label: "Стало", kind: "text" }] },
    { key: "computers", title: "Все компьютеры", kind: "table" }],
  row_key: "entity_id", detail: { kind: "inline", key: "entity_id", title: "Почему на проверке", inline: "reasons", row_links: [],
    columns: [{ key: "label", path: "label", label: "Причина", kind: "text" }] },
  export: true, limits: { default: 50, max: 200 }, presets: [], row_links: [], filter_options: {},
};
const host = { entity_id: 1, display_name: "synthetic-host", domain_name: "example.test", computer_type: "domain_controller", operating_system: "unknown", reasons: [] };
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
function show(props: Partial<Parameters<typeof ReportRenderer>[0]> = {}) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ReportRenderer reportKey={definition.key} {...props}/></QueryClientProvider>);
}
beforeEach(() => {
  requests.length = 0;
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?domain_id=8");
  respond = (params) => params.get("tab") === "checks" ? page() : params.get("tab") === "changes"
    ? page({ items: [{ ...host, row_id: "new:1", change_type: "Synthetic discovery", before: "Absent", after: "Present" }] })
    : page({ state: "ok", items: [host], metrics: [{ key: "all", label: "All", value: 1 }], coverage: {} });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const params = new URL(url, "http://example.test").searchParams;
    if (url.includes("/data?")) requests.push(params);
    return new Response(JSON.stringify(url.includes("/data?") ? respond(params) : definition));
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
  expect(target.searchParams.get("return_to")).toBe("/app/report/ad.computers.v6?domain_id=8");
  link.addEventListener("click", (event) => event.preventDefault(), { once: true });
  fireEvent.click(link);
  expect(onSelect).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "synthetic-host" }));
  expect(onSelect).toHaveBeenCalledExactlyOnceWith(row);
});

it("opens checks first, preserves unknown counts and shows no warning for a fresh complete source", async () => {
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
  expect(container.querySelector(".sli-ds-header__meta")?.textContent ?? "").not.toContain("2026");
  expect(container.querySelectorAll(".sli-ds-state--banner, .sli-ds-callout")).toHaveLength(0);
  fireEvent.click(summary);
  expect(screen.getByRole("button", { name: "synthetic-preview" })).toBeTruthy();
  expect(screen.getByText("Synthetic action", { exact: false })).toBeTruthy();
  expect(screen.queryByText("Synthetic remediation")).toBeNull();
  expect(summary.parentElement?.querySelector("details")).toBeNull();
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

it("opens preview and inventory names in the overlay, keeping the list and closing on Escape", async () => {
  show();
  await screen.findByText(check.title, { selector: "strong" });
  fireEvent.click(screen.getByText(check.title, { selector: "strong" }).closest("summary")!);
  fireEvent.click(screen.getByRole("button", { name: "synthetic-preview" }));
  expect(screen.getByRole("dialog").textContent).toContain("synthetic-preview");
  expect(screen.getByRole("tab", { name: "Требуют проверки" })).toBeTruthy();
  fireEvent.keyDown(document, { key: "Escape" });
  expect(screen.queryByRole("dialog")).toBeNull();
  fireEvent.click(screen.getByRole("tab", { name: "Все компьютеры" }));
  fireEvent.click(await screen.findByRole("button", { name: "synthetic-host" }));
  const drawer = screen.getByRole("dialog");
  expect(drawer.getAttribute("aria-modal")).toBe("true");
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
  expect(requests.every((request) => request.get("domain_id") === "8")).toBe(true);
  fireEvent.click(screen.getByRole("tab", { name: "Все компьютеры" }));
  await screen.findByRole("button", { name: "synthetic-host" });
  expect(screen.queryByText("unknown")).toBeNull();
  expect(screen.getByRole("columnheader", { name: "LAPS" })).toBeTruthy();
});

it("retains cursor pagination on inventory and never shows another tab's rows", async () => {
  respond = (params) => params.get("tab") === "computers"
    ? page({ state: "ok", items: [{ ...host, entity_id: params.get("cursor") ? 2 : 1, display_name: params.get("cursor") ? "synthetic-next" : host.display_name }],
      has_more: !params.get("cursor"), next_cursor: params.get("cursor") ? null : "opaque" }) : page();
  show();
  await screen.findByText(check.title, { selector: "strong" });
  fireEvent.click(screen.getByRole("tab", { name: "Все компьютеры" }));
  await screen.findByRole("button", { name: "synthetic-host" });
  fireEvent.click(screen.getByRole("button", { name: t("table.loadMore") }));
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

it("shows an empty comparison after successful reading without a note", async () => {
  window.history.replaceState(null, "", "/app/report/ad.computers.v6?tab=changes&domain_id=8");
  respond = () => page({ state: "empty", items: [], collections: { changes: [] }, coverage: {
    domains: [{ domain_name: "example.test", state: "complete", observed_at_utc: new Date().toISOString() }] } });
  const { container } = show();
  await screen.findByText(t("reports.ad.computers.no_changes"));
  expect(container.querySelectorAll('.sli-ds-callout[data-tone="warning"]')).toHaveLength(0);
  expect(container.textContent).not.toContain("Synthetic computer changes note");
  expect(screen.getAllByRole("status")).toHaveLength(1);
});


it("keeps low-priority checks in the same list and filters them by importance", () => {
  const { rerender, container } = render(<ComputerChecks result={page({ coverage: { not_evaluated_count: 0 }, items: [
    { ...check, total: 0, is_lower_bound: false },
    { ...check, id: "low", key: "low", title: "Synthetic low-priority check", severity: "low", severity_text: "Низкая", total: 0, is_lower_bound: false },
  ] })} onSelect={vi.fn()} onInventory={vi.fn()}/>);
  expect(container.querySelector(".sli-ds-review-list__total")?.textContent).toBe("0");
  expect(container.querySelector("[role='status']")).toBeNull();
  expect(container.querySelector("details[open]")).toBeNull();
  expect(screen.getByText("Synthetic low-priority check", { selector: "strong" })).toBeTruthy();
  fireEvent.change(screen.getByRole("combobox", { name: t("reports.ad.checks.column.severity") }), { target: { value: "low" } });
  expect(screen.queryByText(check.title)).toBeNull();
  expect(screen.getByText("Synthetic low-priority check", { selector: "strong" })).toBeTruthy();
  rerender(<ComputerChecks result={page({ items: [{ ...check, total: null }] })} onSelect={vi.fn()} onInventory={vi.fn()}/>);
  expect(container.querySelector(".sli-ds-review-list__item")).toBeNull();
  expect(computerRole("unknown")).toBe("—");
});

it("defines identical computer view translations in both locales", () => {
  const keys = Object.keys(ru).filter((key) => key.startsWith("reports.ad.computers.") || key.startsWith("reports.v2.ad.computers.v6.views.changes."));
  expect(Object.keys(en).filter((key) => key.startsWith("reports.ad.computers.") || key.startsWith("reports.v2.ad.computers.v6.views.changes.")).sort()).toEqual(keys.sort());
  for (const key of keys) expect(en[key as keyof typeof en]).not.toMatch(/[А-Яа-яЁё]/);
});

