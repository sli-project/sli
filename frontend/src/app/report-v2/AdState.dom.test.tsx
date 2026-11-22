// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import definitions from "../../../../server-dotnet/src/Sli.Server/Ad/report-definitions.json";
import { api } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale } from "../../i18n";
import { ReportRenderer } from "./ReportRenderer";

const definition = definitions["ad.infrastructure"].declaration as unknown as ReportDefinitionDto;
const observed = "2026-11-22T01:45:00Z";
const controls = [
  { row_id: "7:password.minimum_length", control_id: "password.minimum_length", label: "Minimum password length", entity_id: 7, entity_type: "password_policy", domain_name: "example.test", actual_value: 16, actual_text: "16", expected_condition: "≥ 12 characters", qualification: "passed", observed_at_utc: observed },
  { row_id: "7:password.lockout_threshold", control_id: "password.lockout_threshold", label: "Lockout threshold", entity_id: 7, entity_type: "password_policy", domain_name: "example.test", actual_value: 0, actual_text: "0", qualification: "failed", observed_at_utc: observed },
  { row_id: "8:dc.dns", label: "DNS", entity_id: 8, entity_type: "domain_controller", entity_name: "dc01.example.test", actual_value: "passed", actual_text: "Passed", qualification: "passed", observed_at_utc: observed },
  { row_id: "8:dc.services", label: "Required services", entity_id: 8, entity_type: "domain_controller", entity_name: "dc01.example.test", actual_value: "not_collected", actual_text: "Not collected", qualification: "not_evaluated" },
];

function result(items: ReportResultDto["items"] = [], collections?: ReportResultDto["collections"]): ReportResultDto {
  return { contract_id: "sli.report-result.v2", report_key: definition.key, state: "ok", items, collections,
    has_more: false, next_cursor: null, filtered_count: items.length, metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {} };
}

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  window.history.replaceState(null, "", "/app/report/ad.infrastructure?domain=2");
  vi.spyOn(api, "reportV2Definition").mockResolvedValue(definition);
  vi.spyOn(api, "reportV2Data").mockImplementation(async (_, params) => {
    if (params.get("tab") === "spn_collisions") return result([], { spn_collisions: [] });
    if (params.get("tab") === "semantic") return result([], { semantic: [{ finding_id: 23, entity_name: "example.test", title: "Lockout threshold disabled", severity: "low", last_seen_utc: observed }] });
    if (params.get("tab") === "parameter_changes") return { ...result([], { parameter_changes: [{ ...controls[0], previous_value: 14, previous_text: "14" }] }), filtered_count: 1 };
    return result(controls);
  });
  vi.spyOn(api, "reportV2Detail").mockResolvedValue(result([
    { observed_at_utc: observed, actual_value: 16, actual_text: "16" },
    { observed_at_utc: "2026-11-09T04:20:00Z", actual_value: 14, actual_text: "14" },
  ]));
});

afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function renderReport() {
  return render(<QueryClientProvider client={new QueryClient()}><ReportRenderer reportKey={definition.key}/></QueryClientProvider>);
}

it("groups observed parameters, puts deviations first, and combines the filters", async () => {
  renderReport();
  await screen.findByRole("button", { name: "All 3" });
  expect(screen.queryByText("Required services")).toBeNull();
  expect(screen.getByText("Lockout threshold").compareDocumentPosition(screen.getByText("Minimum password length")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Deviations 1" }));
  expect(screen.queryByText("Minimum password length")).toBeNull();
  expect(screen.getByText("Lockout threshold")).toBeTruthy();
  expect(new URL(screen.getByRole("link", { name: "Export CSV" }).getAttribute("href")!, window.location.origin).searchParams.get("qualification")).toBe("failed");
  fireEvent.click(screen.getByRole("button", { name: "Matches 2" }));
  fireEvent.change(screen.getByRole("combobox", { name: "Area" }), { target: { value: "password_policy" } });
  expect(screen.queryByText("DNS")).toBeNull();
  fireEvent.change(screen.getByRole("searchbox", { name: "Parameter or object" }), { target: { value: "no match" } });
  expect(screen.queryByText("Minimum password length")).toBeNull();
});

it("opens only the parameter named by a domain-scoped deep link", async () => {
  window.history.replaceState(null, "", "/app/report/ad.infrastructure?domain=2&row_id=7%3Apassword.minimum_length");
  renderReport();
  await screen.findByRole("table", { name: /Value history · Minimum password length/ });
  expect(screen.getAllByRole("table", { name: /Value history/ })).toHaveLength(1);
  expect(vi.mocked(api.reportV2Detail).mock.calls[0][1]).toBe("7:password.minimum_length");
});

it("expands and collapses a parameter with history from the same domain", async () => {
  renderReport();
  const toggle = await screen.findByRole("button", { name: "Minimum password length" });
  expect(api.reportV2Detail).not.toHaveBeenCalled();
  fireEvent.click(toggle);
  const history = await screen.findByRole("table", { name: "Value history · Minimum password length · example.test" });
  expect(await within(history).findByText(/14 characters/)).toBeTruthy();
  expect(vi.mocked(api.reportV2Detail).mock.calls[0][2].get("domain")).toBe("2");
  expect(toggle.getAttribute("aria-expanded")).toBe("true");
  fireEvent.click(toggle);
  expect(screen.queryByRole("table", { name: /Value history/ })).toBeNull();
});

it.each([
  { entry: "selection", locale: "en", label: "Lockout threshold", title: "Value history", loading: "Loading data…", value: "20 attempts" },
  { entry: "deep link", locale: "ru", label: "Порог блокировки", title: "История значения", loading: "Загружаем данные…", value: "20 поп." },
] as const)("loads one lockout threshold observation from a cold $entry", async ({ entry, locale, label, title, loading, value }) => {
  const parameter = { ...controls[1], label, actual_value: 20, actual_text: "20", expected_condition: "5–10" };
  const address = "/app/report/ad.infrastructure?domain=2&period=24h";
  window.history.replaceState(null, "", entry === "deep link" ? `${address}&row_id=${encodeURIComponent(parameter.row_id)}` : address);
  setLocale(locale);
  vi.mocked(api.reportV2Data).mockImplementation(async (_, params) => result(params.get("tab") === "controls" ? [parameter] : []));
  vi.mocked(api.reportV2Detail).mockRestore();
  let sendResponse!: (response: Response) => void;
  const response = new Promise<Response>((resolve) => { sendResponse = resolve; });
  const fetchDetail = vi.fn<typeof fetch>(() => response);
  vi.stubGlobal("fetch", fetchDetail);

  renderReport();
  const toggle = await screen.findByRole("button", { name: label });
  if (entry === "selection") fireEvent.click(toggle);
  const heading = await screen.findByRole("heading", { name: `${title} · ${label} · example.test` });
  const history = within(heading.closest("section")!);
  const loadingState = { hasTable: Boolean(history.queryByRole("table")), announcement: history.queryByRole("status")?.textContent };
  expect(toggle.getAttribute("aria-expanded")).toBe("true");
  await waitFor(() => expect(fetchDetail).toHaveBeenCalledTimes(1));
  const request = new URL(String(fetchDetail.mock.calls[0][0]), window.location.origin);
  expect(request.pathname).toBe("/api/v2/reports/ad.infrastructure/rows/7%3Apassword.lockout_threshold/detail");
  expect(request.searchParams.get("domain")).toBe("2");
  expect(request.searchParams.has("row_id")).toBe(false);

  sendResponse(Response.json(result([{ row_id: 1, observed_at_utc: observed, actual_value: 20, actual_text: "20" }])));
  const table = await history.findByRole("table");
  expect(await within(table).findByRole("cell", { name: value })).toBeTruthy();
  expect(within(table).getAllByRole("row")).toHaveLength(2);
  expect(history.queryByRole("status")).toBeNull();
  expect(loadingState).toEqual({ hasTable: false, announcement: loading });
});

it("keeps a failed history distinct from a settled empty result after retry", async () => {
  vi.mocked(api.reportV2Detail).mockRejectedValueOnce(new Error("History request failed"))
    .mockResolvedValueOnce({ ...result(), state: "empty" });
  renderReport();
  fireEvent.click(await screen.findByRole("button", { name: "Minimum password length" }));
  const error = await screen.findByRole("alert");
  expect(screen.queryByRole("table", { name: /Value history/ })).toBeNull();
  fireEvent.click(within(error).getByRole("button", { name: "Retry" }));
  const history = await screen.findByRole("table", { name: /Value history · Minimum password length/ });
  expect(within(history).getByRole("cell", { name: "—" })).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
});

it("switches to SPN collisions and linked findings using their report collections", async () => {
  renderReport();
  fireEvent.click(await screen.findByRole("tab", { name: "SPN collisions 0" }));
  expect(await screen.findByText("No SPN collisions")).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: "Linked findings 1" }));
  expect(await screen.findByText("Lockout threshold disabled")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Open problem" }).getAttribute("href")).toContain("id=23");
  fireEvent.click(screen.getByRole("tab", { name: "AD changes 1" }));
  expect(await screen.findByText(/14 characters →/)).toBeTruthy();
  expect(screen.getByText("Snapshot comparison")).toBeTruthy();
});
