// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import definitions from "../../../../server-dotnet/src/Sli.Server/Ad/report-definitions.json";
import { api, ApiResponseError } from "../../api/client";
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

it.each([
  ["parameter_changes", "AD changes", "No AD changes in the selected period"],
  ["spn_collisions", "SPN collisions", "No SPN collisions"],
  ["semantic", "Linked findings", "No linked findings in the selected period"],
])("shows a tab-specific line for an empty %s result", async (key, tab, phrase) => {
  vi.mocked(api.reportV2Data).mockImplementation(async (_, params) => params.get("tab") === key
    ? { ...result(), state: "empty" }
    : result(controls));
  renderReport();
  fireEvent.click(await screen.findByRole("tab", { name: new RegExp(tab) }));
  const table = await screen.findByRole("table", { name: tab });
  expect(await within(table).findByRole("cell", { name: phrase })).toBeTruthy();
});

it("accepts the legacy all view on a domain-scoped AD URL", async () => {
  const rowId = controls[1].row_id;
  const previous = "/app/report/events.journal?domain=2&view=all&sort=observed_at_utc&cursor=previous";
  window.history.replaceState(null, "", previous);
  const entry = { index: 1 };
  window.history.pushState(entry, "", `/app/report/ad.infrastructure?domain=2&period=24h&view=all&row_id=${encodeURIComponent(rowId)}&return_to=%2Fapp%2Freport%2Fevents.journal&sort=observed_at_utc&cursor=foreign#check`);
  const historyLength = window.history.length;
  vi.mocked(api.reportV2Data).mockRestore();
  const allowedViews = definition.params.find(({ key }) => key === "view")!.options!.map(({ value }) => value);
  const fetchData = vi.fn<typeof fetch>(async (input) => {
    const params = new URL(String(input), window.location.origin).searchParams;
    if (params.has("view") && !allowedViews.includes(params.get("view")!)) {
      return Response.json({ detail: "invalid report view" }, { status: 400 });
    }
    return Response.json(params.get("tab") === "controls" ? result(controls) : result());
  });
  vi.stubGlobal("fetch", fetchData);

  const { unmount } = renderReport();
  const requests = () => fetchData.mock.calls.map(([url]) => new URL(String(url), window.location.origin).searchParams);
  await waitFor(() => expect(requests().some((params) => params.get("tab") === "controls")).toBe(true));
  const controlsRequest = requests().find((params) => params.get("tab") === "controls")!;
  expect(controlsRequest.get("view")).toBe("overview");
  expect(controlsRequest.get("domain")).toBe("2");
  expect(controlsRequest.get("period")).toBe("24h");
  expect(controlsRequest.has("return_to")).toBe(false);
  expect(requests().filter((params) => params.get("tab") !== "controls").every((params) => !params.has("view"))).toBe(true);
  expect(await screen.findByRole("table", { name: /Value history · Lockout threshold/ })).toBeTruthy();
  expect(vi.mocked(api.reportV2Detail).mock.calls[0][1]).toBe(rowId);
  const current = new URL(window.location.href);
  expect(current.searchParams.get("view")).toBe("overview");
  expect(current.searchParams.get("return_to")).toBe("/app/report/events.journal");
  expect(current.searchParams.has("sort")).toBe(false);
  expect(current.searchParams.has("cursor")).toBe(false);
  expect(current.hash).toBe("#check");
  expect(window.history.length).toBe(historyLength);
  expect(window.history.state).toEqual(entry);
  unmount();
  window.history.back();
  await waitFor(() => expect(window.location.pathname + window.location.search).toBe(previous));
  window.history.forward();
  await waitFor(() => expect(window.location.href).toBe(current.href));
});

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
  await chooseOption(screen.getByLabelText("Area", { selector: "button" }), "password_policy");
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

it("opens check details by keyboard without moving history out of its row", async () => {
  const row = { ...controls[1], actual_value: 20, expected_condition: "5–10", authority_text: "Report rule", domain_entity_id: 42 };
  vi.mocked(api.reportV2Data).mockImplementation(async (_, params) => result(params.get("tab") === "controls" ? [row] : []));
  renderReport();
  const toggle = await screen.findByRole("button", { name: "Lockout threshold" });
  toggle.focus();
  fireEvent.click(toggle);
  const drawer = within(await screen.findByRole("complementary", { name: "Lockout threshold" }));
  const observation = drawer.getByRole("tab", { name: "Observation" });
  expect(drawer.getByText("20 attempts")).toBeTruthy();
  expect(drawer.getByText("5–10")).toBeTruthy();
  const history = await screen.findByRole("table", { name: /Value history · Lockout threshold/ });
  expect(history.closest("tr[data-detail]")).toBeTruthy();
  observation.focus();
  fireEvent.keyDown(observation, { key: "ArrowRight" });
  expect(drawer.getByRole("tab", { name: "Object", selected: true })).toBe(document.activeElement);
  expect(drawer.getByRole("link", { name: "example.test" }).getAttribute("href")).toContain("/app/entities/42");
  expect(drawer.getByRole("heading", { name: "Affected objects" })).toBeTruthy();
  expect(drawer.getByText("—")).toBeTruthy();
  fireEvent.keyDown(document.activeElement!, { key: "ArrowRight" });
  expect(drawer.getByText("Report rule")).toBeTruthy();
  fireEvent.keyDown(document.activeElement!, { key: "Escape" });
  expect(screen.queryByRole("complementary", { name: "Lockout threshold" })).toBeNull();
  expect(document.activeElement).toBe(toggle);
  expect(history.isConnected).toBeTruthy();
});

it("links a failed controller check to the controller that was actually checked", async () => {
  const row = { ...controls[2], actual_value: "failed", qualification: "failed", domain_id: 2,
    object_context: { dns_host_name: "dc01.example.test" }, authority: "collector_diagnostic" };
  vi.mocked(api.reportV2Data).mockImplementation(async (_, params) => result(params.get("tab") === "controls" ? [row] : []));
  renderReport();
  fireEvent.click(await screen.findByRole("button", { name: "DNS" }));
  const drawer = within(await screen.findByRole("complementary", { name: "DNS" }));
  fireEvent.click(drawer.getByRole("tab", { name: "Object" }));
  const affected = within(drawer.getByRole("region", { name: "Affected objects" }));
  const [controller] = affected.getAllByRole("link");
  expect(controller.textContent).toBe("dc01.example.test");
  const target = new URL(controller.getAttribute("href")!, window.location.origin);
  expect(target.pathname).toBe("/app/entities/8");
  expect(target.searchParams.get("return_to")).toContain("domain=2");
  expect(drawer.getByRole("link", { name: "Object events" }).getAttribute("href")).toContain("domain=2");
});

it("lists distinct confirmed SPN owners in their own domain and snapshot", async () => {
  const owner = { domain_id: 2, run_id: "run-a", spn: "HTTP/svc.example.test", normalized_spn: "http/svc.example.test", owner_count: 2, observed_at_utc: observed };
  vi.mocked(api.reportV2Data).mockImplementation(async (_, params) => params.get("tab") === "spn_collisions"
    ? { ...result([], { spn_collisions: [
      { ...owner, entity_id: 42, entity_name: "account-a" },
      { ...owner, entity_id: 42, entity_name: "account-a" },
      { ...owner, entity_id: 43, entity_name: "account-b" },
      { ...owner, entity_id: 52, entity_name: "other-domain", domain_id: 5 },
      { ...owner, entity_id: 62, entity_name: "other-run", run_id: "run-b" },
    ] }), state: "partial" }
    : result(params.get("tab") === "controls" ? controls : []));
  renderReport();
  fireEvent.click(await screen.findByRole("tab", { name: "SPN collisions 3" }));
  fireEvent.click((await screen.findAllByRole("button", { name: "HTTP/svc.example.test" }))[0]);
  const drawer = within(await screen.findByRole("complementary", { name: "HTTP/svc.example.test" }));
  fireEvent.click(drawer.getByRole("tab", { name: "Object" }));
  const links = within(drawer.getByRole("region", { name: "Affected objects" })).getAllByRole("link");
  expect(links.map((link) => link.textContent)).toEqual(["account-a", "account-b"]);
  expect(links.map((link) => link.getAttribute("href")?.split("?")[0])).toEqual(["/app/entities/42", "/app/entities/43"]);
});

it("keeps existing history after a final empty page and drops the stale continuation", async () => {
  vi.mocked(api.reportV2Detail)
    .mockResolvedValueOnce({ ...result([{ row_id: 1, actual_value: 16, observed_at_utc: observed }]), has_more: true, next_cursor: "1" })
    .mockResolvedValueOnce({ ...result(), state: "empty", has_more: true, next_cursor: "1" });
  renderReport();
  fireEvent.click(await screen.findByRole("button", { name: "Minimum password length" }));
  const historyHeading = await screen.findByRole("heading", { name: /Value history · Minimum password length/ });
  const history = within(historyHeading.closest("section")!);
  const more = await history.findByRole("button", { name: "Show more" });
  fireEvent.click(more);
  await waitFor(() => expect(history.queryByRole("button", { name: "Show more" })).toBeNull());
  expect(history.getByRole("cell", { name: "16 characters" })).toBeTruthy();
  expect(vi.mocked(api.reportV2Detail).mock.calls[1][2].get("cursor")).toBe("1");
});

it("shows an unavailable history as a recoverable failure", async () => {
  vi.mocked(api.reportV2Detail).mockResolvedValueOnce({ ...result(), state: "not_collected" })
    .mockResolvedValueOnce({ ...result(), state: "empty" });
  renderReport();
  fireEvent.click(await screen.findByRole("button", { name: "Minimum password length" }));
  const unavailable = await screen.findByRole("alert");
  expect(unavailable.textContent).toContain("Could not load Value history");
  fireEvent.click(within(unavailable).getByRole("button", { name: "Retry" }));
  expect(await screen.findByRole("table", { name: /Value history · Minimum password length/ })).toBeTruthy();
});

it("hides a deep-linked check and its history when the domain is denied", async () => {
  window.history.replaceState(null, "", "/app/report/ad.infrastructure?domain=5&view=all&row_id=7%3Apassword.lockout_threshold");
  vi.mocked(api.reportV2Data).mockImplementation(async (_, params) => params.get("tab") === "controls"
    ? { ...result([controls[1]]), state: "denied" }
    : result());
  renderReport();
  await screen.findByRole("link", { name: "My access" });
  expect(screen.queryByRole("button", { name: "Lockout threshold" })).toBeNull();
  expect(screen.queryByRole("complementary", { name: "Lockout threshold" })).toBeNull();
  expect(api.reportV2Detail).not.toHaveBeenCalled();
});

it("preserves confirmed history while retrying an unavailable continuation", async () => {
  const firstPage = { ...result([{ row_id: 1, actual_value: 16, observed_at_utc: observed }]), state: "partial" as const, has_more: true, next_cursor: "1" };
  vi.mocked(api.reportV2Detail).mockResolvedValueOnce(firstPage)
    .mockRejectedValueOnce(new ApiResponseError(503, "report_read_timeout"))
    .mockResolvedValueOnce(result([{ row_id: 2, actual_value: 14, observed_at_utc: "2026-11-09T04:20:00Z" }]));
  renderReport();
  fireEvent.click(await screen.findByRole("button", { name: "Minimum password length" }));
  fireEvent.click(await screen.findByRole("button", { name: "Show more" }));
  const failure = await screen.findByRole("alert");
  const history = screen.getByRole("table", { name: /Value history · Minimum password length/ });
  expect(within(history).getByRole("cell", { name: "16 characters" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Show more" })).toBeNull();
  fireEvent.click(within(failure).getByRole("button", { name: "Retry" }));
  expect(await within(history).findByRole("cell", { name: "14 characters" })).toBeTruthy();
  expect(vi.mocked(api.reportV2Detail).mock.calls.map(([, , query]) => query.get("cursor"))).toEqual([null, "1", "1"]);
});
