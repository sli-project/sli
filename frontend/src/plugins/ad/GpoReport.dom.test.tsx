// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ReportRenderer } from "../../app/report-v2/ReportRenderer";
import gpoDeclaration from "../../../../server-dotnet/src/Sli.Server/Gpo/declaration.json";

const definition = { ...gpoDeclaration.declaration, filter_options: {} } as unknown as ReportDefinitionDto;
const items = Array.from({ length: 11 }, (_, index) => ({ id: `fixture-${index}`, guid: `fixture-${index}`, display_name: `GPO ${index + 1}`,
  gpo_status: "AllSettingsEnabled", reason_titles: index === 0 ? "Synthetic version mismatch" : null, link_count: 1, modification_time: "2026-11-13T12:00:00Z", owner: "fixture-owner" }));
let response: ReportResultDto;
const requests: URL[] = [];

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  requests.length = 0;
  window.history.replaceState(null, "", "/app/report/ad.gpo.v2?domain_id=7");
  response = { contract_id: "sli.report-result.v2", report_key: definition.key, state: "partial", items,
    filtered_count: 11, has_more: false, next_cursor: null, series: {}, window: {}, filter_options: {},
    coverage: { observed_at_utc: "2026-11-13T12:00:00Z", completeness: "not_proven" },
    state_details: { reason: "freshness_exceeded", source: "dc01.example.test", stale_since_utc: "2026-11-13T12:00:00Z" },
    limitations: [{ code: "fixture", text: "Removed collection explanation" }],
    metrics: ["attention", "unverified", "assignment", "all", "linked", "unlinked"].map((view) => ({ key: view,
      label: `Removed tile ${view}`, value: ["attention", "unlinked"].includes(view) ? 0 : 11, filter: { view } })),
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), window.location.origin);
    requests.push(url);
    return new Response(JSON.stringify(url.pathname.endsWith("/data")
      ? url.searchParams.get("view") === "attention" ? { ...response, state: "empty", items: [], filtered_count: 0 } : response
      : definition), { headers: { "Content-Type": "application/json" } });
  }));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

function renderReport() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <ReportRenderer reportKey="ad.gpo.v2"/>
  </QueryClientProvider>);
}

it.each(["ru", "en"] as const)("opens all policies with the passport columns and no collection blocks (%s)", async (locale) => {
  setLocale(locale);
  renderReport();
  const table = await screen.findByRole("table");
  expect(within(table).getAllByRole("row")).toHaveLength(12);
  expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent?.replace(/↕/g, ""))).toEqual(locale === "ru"
    ? ["Политика", "Состояние", "Замечания", "Связи", "Изменена", "Владелец"]
    : ["Policy", "State", "Remarks", "Links", "Modified", "Owner"]);
  expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual(locale === "ru"
    ? ["Политики", "Изменения", "Области применения"] : ["Policies", "Changes", "Linked scopes"]);
  expect(within(table).getByText("Synthetic version mismatch")).toBeTruthy();
  expect(within(table).getAllByText("fixture-owner")).toHaveLength(items.length);
  const filters = screen.getByRole("group", { name: t("reports.renderer.quick_scenarios") });
  expect(within(filters).getAllByRole("button").map((button) => button.textContent)).toEqual(locale === "ru"
    ? ["Все 11", "С замечаниями", "Без связей"] : ["All 11", "With remarks", "Unlinked"]);
  expect(document.querySelectorAll(".sli-ds-metrics, .sli-ds-state--banner, .sli-ds-callout, .sli-ds-header p, .sli-ds-header details")).toHaveLength(0);
  expect(screen.queryByText("Removed collection explanation")).toBeNull();
  expect(screen.queryByText(/Removed tile/)).toBeNull();
  expect(screen.queryByText(/Молчит источник|does not send/)).toBeNull();
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("7");
  const data = requests.find((url) => url.pathname.endsWith("/data"))!;
  expect(data.searchParams.get("view")).toBe("all");
  expect(data.searchParams.has("domain")).toBe(false);
  expect(data.searchParams.has("domain_id")).toBe(false);
  expect(data.searchParams.has("period")).toBe(false);
  fireEvent.click(within(filters).getByRole("button", { name: t("reports.v2.ad.gpo.v2.params.view.options.attention") }));
  await screen.findByText(t("reports.ad.gpo.empty"));
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.getAllByRole("status").map((element) => element.textContent)).toEqual([t("reports.ad.gpo.empty")]);
  expect(screen.queryByRole("button", { name: /Показать последние|latest/i })).toBeNull();
  expect(screen.queryByRole("link", { name: /Диагностика|diagnostics/i })).toBeNull();
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("7");
  fireEvent.click(within(filters).getByRole("button", { name: locale === "ru" ? "Все 11" : "All 11" }));
  await screen.findByRole("table");
});

it("opens allowed history and scopes, preserving the period and export conditions", async () => {
  response.collections = { changes: [{ observed_at: "2026-11-13T12:00:00Z", object_type: "gpo", object_id: "fixture-0", kind: "object_added" }],
    linked_scopes: [{ gpo_name: "GPO 1", scope_name: "example.test", scope_type: "domain", enabled: true }] };
  renderReport();
  await screen.findByRole("table");
  fireEvent.click(screen.getByRole("tab", { name: "Изменения" }));
  await screen.findByRole("table", { name: "Изменения" });
  expect(screen.getAllByRole("columnheader").length).toBeLessThanOrEqual(7);
  expect(screen.queryByText(definition.views.find((view) => view.key === "changes")!.note!)).toBeNull();
  await waitFor(() => expect(requests.some((url) => url.searchParams.get("tab") === "changes" && url.searchParams.get("period") === "7d")).toBe(true));
  fireEvent.click(screen.getByRole("tab", { name: "Области применения" }));
  await screen.findByRole("table", { name: "Области применения" });
  expect(screen.getAllByRole("columnheader").length).toBeLessThanOrEqual(7);
  const params = new URL(screen.getByRole("link", { name: "Экспорт CSV" }).getAttribute("href")!, window.location.origin).searchParams;
  expect(params.get("tab")).toBe("linked_scopes");
  expect(params.has("period")).toBe(false);
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("7");
});

it("falls back from a hidden tab to policies and retains explicit filters", async () => {
  window.history.replaceState(null, "", "/app/report/ad.gpo.v2?tab=quality&view=unlinked&q=GPO&domain=7");
  renderReport();
  await screen.findByRole("table", { name: "Политики" });
  expect(requests.some((url) => url.searchParams.get("view") === "unlinked" && url.searchParams.get("q") === "GPO")).toBe(true);
  expect(new URLSearchParams(window.location.search).has("tab")).toBe(false);
});
