// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import definitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ReportRenderer } from "./ReportRenderer";

const definition = { ...definitions.find((item) => item.key === "events.journal"), filter_options: {} } as unknown as ReportDefinitionDto;
const windowBounds = { from_utc: "2026-11-22T00:00:00Z", to_utc_exclusive: "2026-11-22T02:00:00Z" };
const event = (id: number, title: string, fields = {}) => ({
  id, title_text: title, event_id: 4624, time_created_utc: "2026-11-22T01:30:05Z",
  target: "dc01.example.test", journal_account: "EXAMPLE\\synthetic.user", journal_computer: "dc01.example.test",
  journal_address: "192.0.2.10", journal_initiator: "EXAMPLE\\operator", logon_type: "3", journal_result: "success", ...fields,
});
const group = event(3, "Logon failed", {
  event_id: 4625, event_count: 18, journal_expandable: true, journal_result: "failure",
  first_seen_utc: "2026-11-22T01:15:00Z", last_seen_utc: "2026-11-22T01:20:00Z",
});
const exact = event(4, "Logon succeeded", { journal_finding_id: 42 });
const preceding = event(2, "Previous logon failure", { event_id: 4625, journal_result: "failure" });

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  window.history.replaceState(null, "", "/app/report/events.journal?domain=7");
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function journal({
  state = "ok", items = [exact, group], failure, pages = false, filterEvidence = false,
}: { state?: ReportResultDto["state"]; items?: Record<string, unknown>[]; failure?: "definition" | "data"; pages?: boolean; filterEvidence?: boolean } = {}) {
  const requests: URL[] = [];
  const data: ReportResultDto = {
    contract_id: "sli.report-result.v2", report_key: "events.journal", state, items,
    has_more: pages, next_cursor: pages ? "next" : null, filtered_count: pages ? 51 : items.length,
    journal_event_count: 19, journal_counts: { all: 19, authentication: 19, failures: 18, service: 0 },
    metrics: [], series: {}, filter_options: {}, coverage: { completeness: "not_proven" },
    state_details: { reason: "freshness_exceeded" }, limitations: [{ code: "synthetic", text: "Synthetic methodology" }],
    window: windowBounds,
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), window.location.origin);
    requests.push(url);
    const params = url.searchParams;
    const isData = url.pathname.endsWith("/data");
    const failed = failure === (isData ? "data" : "definition");
    const payload = url.pathname === "/api/v1/events/4" ? { item: { event_db_id: 4, event_record_id: 30, event_data: { AuthenticationPackageName: "Kerberos" } } }
      : !isData ? definition
      : params.has("before") ? { ...data, items: params.get("before") === "4" ? [preceding] : [] }
      : params.has("expand") ? { ...data, items: [
        event(6, "First source failure", { journal_reported_account: "REPORTED\\synthetic.user" }),
        event(5, "Second source failure", { journal_reported_account: "synthetic.user" }),
      ], next_cursor: null }
      : params.has("cursor") ? { ...data, items: [event(1, "Next page event")], next_cursor: null }
      : params.get("view") === "service" ? { ...data, items: [], state: "empty" }
      : filterEvidence && params.get("hide_open_problem_evidence") === "on"
        ? { ...data, items: [group], filtered_count: 1, journal_counts: { all: 18, authentication: 18, failures: 18, service: 0 } }
        : data;
    return new Response(JSON.stringify(failed ? { error: "synthetic_failure" } : payload), {
      status: failed ? 500 : 200, headers: { "Content-Type": "application/json" },
    });
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <ReportRenderer reportKey="events.journal"/>
  </QueryClientProvider>);
  return requests;
}

it("hides open problem evidence by default and restores its link and counts when unchecked", async () => {
  const requests = journal({ filterEvidence: true });
  const filter = await screen.findByRole("checkbox", { name: "Hide evidence of open problems" });
  expect(filter).toHaveProperty("checked", true);
  await screen.findByRole("tab", { name: "All 18" });
  expect(screen.queryByRole("link", { name: "Problem #42" })).toBeNull();
  fireEvent.click(filter);
  await screen.findByRole("tab", { name: "All 19" });
  expect(await screen.findByRole("link", { name: "Problem #42" })).toBeTruthy();
  expect(requests.at(-1)?.searchParams.get("hide_open_problem_evidence")).toBe("off");
});

it("keeps the workstation source and return context when changing journal filters", async () => {
  const source = "41800000-0000-4000-8000-000000000001";
  const returnTo = `/app/report/workstations.overview?station=41700000-0000-4000-8000-000000000001&source_instance_id=${source}&limit=200&period=30d`;
  const query = new URLSearchParams({ domain: "7", source_instance_id: source, source_plugin: "sli.workstations", return_to: returnTo });
  window.history.replaceState(null, "", `/app/report/events.journal?${query}`);
  const requests = journal();
  await screen.findByText("Logon succeeded");
  expect(screen.getByRole("link", { name: t("investigations.case.return_to_source_report") }).getAttribute("href")).toBe(returnTo);
  fireEvent.click(screen.getByRole("tab", { name: /Service events/ }));
  await screen.findByText(t("reports.v2.events.journal.empty"));
  const dataRequests = requests.filter((url) => url.pathname.endsWith("/data"));
  expect(dataRequests.length).toBeGreaterThanOrEqual(2);
  for (const request of dataRequests) {
    expect(request.searchParams.get("source_instance_id")).toBe(source);
    expect(request.searchParams.get("source_plugin")).toBe("sli.workstations");
    expect(request.searchParams.has("return_to")).toBe(false);
  }
  const normalized = new URLSearchParams(window.location.search);
  expect(normalized.get("return_to")).toBe(returnTo);
  expect(normalized.get("source_instance_id")).toBe(source);
});

it("aborts the pending journal request when the report unmounts", async () => {
  let dataSignal: AbortSignal | undefined;
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (!new URL(String(input), window.location.origin).pathname.endsWith("/data")) return Response.json(definition);
    dataSignal = init?.signal ?? undefined;
    return new Promise<Response>((_resolve, reject) => {
      dataSignal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    });
  }));
  const view = render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <ReportRenderer reportKey="events.journal"/>
  </QueryClientProvider>);
  await waitFor(() => expect(dataSignal?.aborted).toBe(false));
  view.unmount();
  expect(dataSignal?.aborted).toBe(true);
});

it("loads the new route period within the same journal domain and search text", async () => {
  const dataRequests: URLSearchParams[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), window.location.origin);
    if (!url.pathname.endsWith("/data")) return Response.json(definition);
    const params = url.searchParams;
    const main = !params.has("before");
    if (main) dataRequests.push(params);
    const otherPeriod = params.get("period") === "24h";
    return Response.json({
      contract_id: "sli.report-result.v2", report_key: "events.journal", state: "ok",
      items: main ? [event(otherPeriod ? 8 : 7, otherPeriod ? "Second period result" : "First period result")] : [],
      next_cursor: null, has_more: false, filtered_count: 1, metrics: [], series: {}, filter_options: {},
      coverage: { completeness: "not_proven" }, limitations: [], window: windowBounds,
    });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const route = (search: string) => <QueryClientProvider client={client}>
    <ReportRenderer reportKey="events.journal" initialSearch={search}/>
  </QueryClientProvider>;
  const first = "?domain=7&period=2h&q=synthetic";
  const second = "?domain=7&period=24h&q=synthetic";
  const view = render(route(first));
  fireEvent.click(await screen.findByText("First period result"));
  const detail = await screen.findByRole("dialog", { name: "First period result" });

  const equivalent = "?q=synthetic&period=2h&domain=7";
  window.history.replaceState(null, "", "/app/report/events.journal" + equivalent);
  view.rerender(route(equivalent));
  expect(screen.getByRole("dialog", { name: "First period result" })).toBe(detail);
  expect(dataRequests).toHaveLength(1);

  window.history.pushState(null, "", "/app/report/events.journal" + second);
  view.rerender(route(second));
  expect(screen.queryByText("First period result")).toBeNull();
  expect(screen.queryByRole("dialog")).toBeNull();
  await screen.findByText("Second period result");
  expect(dataRequests.map((params) => [params.get("domain"), params.get("period"), params.get("q")]))
    .toEqual([["7", "2h", "synthetic"], ["7", "24h", "synthetic"]]);
  expect(new URLSearchParams(window.location.search).get("period")).toBe("24h");
});

it.each(["ok", "partial", "stale", "processing"] as const)("shows journal facts and server counts without explanatory blocks (%s)", async (state) => {
  const requests = journal({ state });
  await screen.findByText("Logon succeeded");
  expect(screen.queryByRole("columnheader", { name: "Severity" })).toBeNull();
  expect(screen.getByRole("columnheader", { name: t("reports.v2.events.journal.problem") })).toBeTruthy();
  expect(screen.getByRole("tab", { name: /^All/ }).getAttribute("aria-selected")).toBe("true");
  expect(screen.getByRole("tab", { name: /Logon failures/ })).toBeTruthy();
  expect(screen.queryByRole("tab", { name: /Accounts|Groups and rights|Audit/ })).toBeNull();
  expect(screen.queryByText("Synthetic methodology")).toBeNull();
  expect(document.querySelector(".sli-ds-state--banner")).toBeNull();
  const request = requests.find((url) => url.pathname.endsWith("/data"))!;
  expect(request.searchParams.get("domain")).toBe("7");
  expect(request.searchParams.get("period")).toBe("2h");
  expect(request.searchParams.get("collapse")).toBe("on");
  const exportLink = screen.getByRole("link", { name: t("reports.renderer.export_csv") });
  expect(new URL(exportLink.getAttribute("href")!, window.location.href).searchParams.get("domain")).toBe("7");

  fireEvent.click(screen.getByRole("tab", { name: /Service events/ }));
  await screen.findByText(t("reports.v2.events.journal.empty"));
  expect(requests.some((url) => url.searchParams.get("view") === "service")).toBe(true);
});

it("shows distinct subjects and links findings and changes by exact ID", async () => {
  const changed = event(7, "Group membership changed", { event_id: 4728, journal_change_domain: 7,
    journal_account: "<test-group>", journal_address: null, logon_type: null,
    journal_computer: "dc02.example.test", journal_initiator: "EXAMPLE\\other.operator" });
  journal({ items: [exact, group, changed] });
  const row = within((await screen.findByText("×18")).closest("tr")!);
  expect(row.getByText(/(\d{2}):15:00 – \1:20:00/)).toBeTruthy();
  expect(row.getByRole("link", { name: "EXAMPLE\\synthetic.user" })).toBeTruthy();
  expect(row.getByRole("link", { name: "EXAMPLE\\operator" })).toBeTruthy();
  expect(row.getByRole("link", { name: "192.0.2.10" })).toBeTruthy();
  expect(row.getByRole("link", { name: "dc01.example.test" })).toBeTruthy();
  expect(row.getByRole("cell", { name: "Network" })).toBeTruthy();
  expect(row.queryByRole("link", { name: /#\d/ })).toBeNull();
  const finding = screen.getByRole("link", { name: /#42/ });
  expect(finding.getAttribute("href")).toBe("/app/report/security.problems?id=42");
  expect(screen.getByRole("link", { name: "<test-group>" })).toBeTruthy();
  const query = new URL(screen.getByRole("link", { name: t("reports.v2.events.journal.open_change") }).getAttribute("href")!, window.location.href);
  expect(query.pathname).toBe("/app/report/security.events.chains");
  expect(Object.fromEntries(query.searchParams)).toMatchObject({ event_db_id: "7", domain: "7", repeat_mode: "individual",
    from: windowBounds.from_utc, to: windowBounds.to_utc_exclusive });
});

it("renders paired actions, a plain workstation, and only distinguishing columns", async () => {
  journal({ items: [
    event(8, "Credential validation", { event_id: 4625, journal_action: "failed_logon", journal_expandable: true,
      event_count: 1, journal_source_count: 2, journal_finding_id: 43 }),
    event(9, "Credential validation", { event_id: 4776, journal_address: null, journal_workstation: "<reported workstation>" }),
    event(10, "Kerberos service ticket", { event_id: 4769, journal_address: null, logon_type: null }),
    event(11, "Logon succeeded", { journal_action: "privileged_logon", logon_type: "10" }),
  ] });
  const failed = within((await screen.findByText(t("reports.v2.events.journal.action.failed_logon"))).closest("tr")!);
  expect(failed.getByRole("button", { name: "Expand repeats" })).toBeTruthy();
  expect(failed.queryByText("×2")).toBeNull();
  expect(failed.getByRole("link", { name: "Problem #43" }).getAttribute("href")).toBe("/app/report/security.problems?id=43");
  expect(screen.getByText(t("reports.v2.events.journal.action.privileged_logon"))).toBeTruthy();
  expect(screen.getByText(t("reports.v2.events.journal.event.4769"))).toBeTruthy();
  expect(screen.getByRole("cell", { name: "<reported workstation>" })).toBeTruthy();
  expect(screen.queryByRole("link", { name: "<reported workstation>" })).toBeNull();
  expect(screen.getByRole("cell", { name: "RDP" })).toBeTruthy();
  for (const name of ["Computer", "Initiator / on behalf of", "Account", "Time", "Result"])
    expect(screen.queryByRole("columnheader", { name })).toBeNull();
});

it("only loads source rows on expansion and keeps the original query window", async () => {
  const requests = journal();
  await screen.findByText("×18");
  expect(requests.some((url) => url.searchParams.has("expand"))).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: "Expand repeats" }));
  const nested = await screen.findByRole("table", { name: "Expand repeats" });
  const request = requests.find((url) => url.searchParams.has("expand"))!;
  expect(request.searchParams.get("expand")).toBe("3");
  expect(request.searchParams.get("from")).toBe(windowBounds.from_utc);
  expect(request.searchParams.get("to")).toBe(windowBounds.to_utc_exclusive);
  expect(request.searchParams.get("limit")).toBe("25");
  expect(within(nested).getByText("First source failure")).toBeTruthy();
  expect(within(nested).getByText("Second source failure")).toBeTruthy();
  expect(within(nested).getByRole("link", { name: "REPORTED\\synthetic.user" })).toBeTruthy();
  expect(within(nested).getByRole("link", { name: "synthetic.user" })).toBeTruthy();
  expect(within(nested).queryByRole("button", { name: "Expand repeats" })).toBeNull();
  fireEvent.click(screen.getAllByRole("button", { name: "Hide repeats" })[0]);
  expect(screen.queryByText("First source failure")).toBeNull();
  fireEvent.click(screen.getByRole("checkbox", { name: "Collapse repeats" }));
  await waitFor(() => expect(requests.some((url) => url.searchParams.get("collapse") === "off")).toBe(true));
});

it("opens authorized pivots, earlier events and the exact event from the same pane", async () => {
  const requests = journal();
  fireEvent.click(await screen.findByText("Logon succeeded"));
  const detail = await screen.findByRole("dialog");
  const context = within(detail);
  expect(new URL(context.getByRole("link", { name: "Open problem" }).getAttribute("href")!, window.location.href).searchParams.get("id")).toBe("42");
  expect((await context.findByRole("link", { name: "Source event" })).getAttribute("href")).toContain("/app/events/4?");
  fireEvent.click(context.getByRole("tab", { name: "Source event" }));
  expect(context.getByText(/AuthenticationPackageName/).textContent).toContain("Kerberos");
  expect(context.getByRole("heading", { name: "Before this event" })).toBeTruthy();
  fireEvent.click(context.getByRole("button", { name: "Previous logon failure" }));
  expect(await context.findByRole("heading", { name: "Previous logon failure" })).toBeTruthy();
  fireEvent.click(context.getByRole("link", { name: "By address" }));
  await waitFor(() => expect(requests.some((url) => url.searchParams.get("pivot") === "address" && url.searchParams.get("q") === "192.0.2.10")).toBe(true));
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("applies search and result filters in the current domain", async () => {
  const requests = journal();
  await screen.findByText("Logon succeeded");
  fireEvent.change(screen.getByRole("searchbox"), { target: { value: "synthetic.user" } });
  await waitFor(() => expect(requests.some((url) => url.searchParams.get("q") === "synthetic.user")).toBe(true));
  await chooseOption(screen.getByLabelText("Result", { selector: "button" }), "failure");
  await waitFor(() => expect(requests.some((url) => url.searchParams.get("q") === "synthetic.user" &&
    url.searchParams.get("result") === "failure" && url.searchParams.get("domain") === "7")).toBe(true));
});

it("pages with the server cursor and offers the approved row sizes", async () => {
  const requests = journal({ pages: true });
  await screen.findByText("Page 1 of 2");
  fireEvent.click(screen.getByRole("button", { name: t("table.next") }));
  await screen.findByText("Next page event");
  expect(requests.find((url) => url.searchParams.has("cursor"))?.searchParams.get("cursor")).toBe("next");
  fireEvent.click(screen.getByRole("button", { name: t("table.previous") }));
  await screen.findByText("Logon succeeded");
  fireEvent.click(screen.getByRole("button", { name: "100" }));
  await waitFor(() => expect(requests.some((url) => url.searchParams.get("limit") === "100")).toBe(true));
});

it.each([["empty", "No records in the selected period"], ["not_collected", "Journal not loaded"]] as const)("keeps an explicit period and represents %s as one line", async (state, message) => {
  window.history.replaceState(null, "", "/app/report/events.journal?domain=7&period=24h");
  const requests = journal({ state, items: [] });
  await screen.findByText(message);
  expect(document.querySelector(".sli-ds-state")).toBeNull();
  expect(requests.find((url) => url.pathname.endsWith("/data"))!.searchParams.get("period")).toBe("24h");
});

it.each(["definition", "data"] as const)("names and retries the failed %s request", async (failure) => {
  const requests = journal({ failure });
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("Could not load the event journal");
  fireEvent.click(within(alert).getByRole("button", { name: t("state.retry") }));
  await waitFor(() => expect(requests.filter((url) => url.pathname.endsWith("/data") === (failure === "data"))).toHaveLength(2));
});
