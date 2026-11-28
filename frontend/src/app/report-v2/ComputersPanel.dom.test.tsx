// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportResultDto } from "../../api/report-v2-types";
import { formatDateTime } from "../../design-system/format";
import { formatDateTime as formatZonedDateTime } from "../../shared/date-time";
import { t } from "../../i18n";
import { DataTable } from "../../design-system";
import type { ReportColumnDto } from "../../api/report-v2-types";
import { ComputerPanel, computerInventoryColumns } from "./ComputersPanel";

const access = vi.hoisted(() => ({ reports: [] as { report_key: string; allowed: boolean }[], capabilities: [] as string[] }));
vi.mock("../App", () => ({ useEffectiveAccess: () => access }));
vi.mock("../../shared/time-zone", () => ({ useTimeZone: () => ({ timeZone: "UTC" }) }));

afterEach(() => {
  cleanup();
  access.reports = [];
  vi.restoreAllMocks();
});

const workstation = { entity_id: 7, display_name: "PC-TEST", computer_type: "workstation" };

it("shows observed computer facts and uses dashes for missing inventory cells", () => {
  const logon = "2026-01-12T10:49:00Z";
  const keys = ["display_name", "computer_type", "operating_system", "last_logon_utc"];
  const columns = keys.map((key): ReportColumnDto => ({ key, path: key, label: key, kind: "text" }));
  const rows = [{ ...workstation, operating_system: "Windows 11 Pro", last_logon_utc: logon },
    { entity_id: 8, display_name: "PC-EMPTY", computer_type: "unknown" }];
  render(<DataTable caption="Computers" columns={computerInventoryColumns(columns, "UTC", vi.fn())}
    rows={rows}
    rowKey={(row) => String(row.entity_id)}/>);
  const filled = within(screen.getByRole("row", { name: /PC-TEST/ }));
  expect(filled.getByText(t("reports.v2.ad.computers.v6.columns.computer_type.labels.workstation"))).toBeTruthy();
  expect(filled.getByText("Windows 11 Pro")).toBeTruthy();
  expect(filled.getByText(formatDateTime(logon, true, "UTC"))).toBeTruthy();
  const empty = within(screen.getByRole("row", { name: /PC-EMPTY/ }));
  expect(empty.getAllByRole("cell").slice(1).map((cell) => cell.textContent)).toEqual(["—", "—", "—"]);
});
it("shows the agent version and last contact in the inventory", () => {
  const stamp = "2026-01-12T10:49:00Z";
  const time = formatZonedDateTime(stamp, "UTC", { withYear: false });
  const columns: ReportColumnDto[] = [{ key: "sli_agent", path: "sli_agent", label: "SLI agent", kind: "text" }];
  const rows = [
      { entity_id: 1, sli_agent: { state: "installed", version: "1.2.3", last_seen_utc: stamp } },
      { entity_id: 2, sli_agent: { state: "silent", version: "2.3.4", last_seen_utc: stamp } },
      { entity_id: 3, sli_agent: { state: "absent" } },
      { entity_id: 4, sli_agent: { state: "unknown" } },
    ];
  render(<DataTable caption="Computers" columns={computerInventoryColumns(columns, "UTC", vi.fn())}
    rows={rows} rowKey={(row) => String(row.entity_id)}/>);
  expect(screen.getAllByRole("cell").map((cell) => cell.textContent)).toEqual([
    `1.2.3 · ${t("reports.computers.agent_connected", { time })}`,
    `2.3.4 · ${t("reports.computers.agent_silent", { time })}`,
    t("reports.ad.additions.agent.absent"),
    "—",
  ]);
});

const observation = (rowId: string, minute: string, event: number | null = 81) => ({
  row_id: rowId, observed_at_utc: `2026-01-12T10:${minute}:00Z`, user_name: "EXAMPLE\\test", source_event_id: event,
});

function page(items: ReportResultDto["items"], cursor: string | null = null): ReportResultDto {
  return {
    contract_id: "sli.report-result.v2", report_key: "ad.computer-logons", state: "ok", items,
    has_more: cursor !== null, next_cursor: cursor, filtered_count: null,
    metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
  };
}

it("uses the available last logon in the computer card when the replicated timestamp is missing", () => {
  const lastLogon = "2026-01-12T10:49:00Z";
  const client = new QueryClient();
  const { container } = render(<QueryClientProvider client={client}>
    <ComputerPanel row={{ ...workstation, ad_last_logon_utc: null, last_logon_utc: lastLogon, last_logon_source: "domain_controllers" }}
      logons={false} logonParams="" onClose={() => {}} timeZone="UTC"/>
  </QueryClientProvider>);
  expect(screen.getByRole("tab", { name: t("reports.computers.important"), selected: true })).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: t("reports.computers.details") }));
  expect(screen.getByText(t("reports.computers.last_logon"))).toBeTruthy();
  expect(screen.getByText(`${formatDateTime(lastLogon, true, "UTC")} · ${t("reports.computers.last_logon_source.domain_controllers")}`)).toBeTruthy();
  expect(container.textContent).not.toContain("lastLogonTimestamp");
});

it("links to the exact computer's domain changes and uses the destination report count", async () => {
  access.reports = [{ report_key: "security.events.chains", allowed: true }];
  const read = vi.spyOn(api, "reportV2Data").mockResolvedValue({ ...page([]), filtered_count: 12 });
  const from = "2026-01-01T00:00:00Z";
  const to = "2026-01-05T00:00:00Z";
  const params = new URLSearchParams({ period: "custom", from, to, tz: "UTC" });
  render(<QueryClientProvider client={new QueryClient()}>
    <ComputerPanel row={{ ...workstation, domain_id: 7 }} logons={false}
      logonParams={params.toString()} onClose={() => {}} timeZone="UTC"/>
  </QueryClientProvider>);
  const link = await screen.findByRole("link", { name: /12/ });
  const url = new URL(link.getAttribute("href")!, "http://example.test");
  expect(url.pathname).toBe("/app/report/security.events.chains");
  expect(Object.fromEntries(url.searchParams)).toEqual({
    period: "custom", from, to, domain: "7", entity_id: "7", changes_view: "all", repeat_mode: "collapsed",
  });
  const [report, request] = read.mock.calls[0];
  expect(report).toBe("security.events.chains");
  expect(Object.fromEntries(request)).toEqual({ ...Object.fromEntries(url.searchParams), limit: "1", tz: "UTC" });
  expect(screen.queryByRole("tab", { name: /changes|изменения/i })).toBeNull();
});

it("hides value-less columns and highlights the field that matched the inventory search", () => {
  const rows = [{ ...workstation, computer_type: "unknown", dns_host_name: "pc-test.example.test" }];
  const columns = ["display_name", "computer_type", "operating_system"].map((key): ReportColumnDto =>
    ({ key, path: key, label: key, kind: "text" }));
  render(<DataTable caption="Computers" columns={computerInventoryColumns(columns, "UTC", vi.fn(), "example")}
    rows={rows} rowKey={() => "7"}/>);
  expect(screen.getAllByRole("columnheader")).toHaveLength(1);
  expect(screen.getByText("example", { selector: "mark" })).toBeTruthy();
});

it("hides the source column for local logons", async () => {
  const local = { ...observation("101", "53"), source: "pc-test.", workstation_name: "pc-test.", repeat_count: 1 };
  vi.spyOn(api, "reportV2Detail").mockResolvedValue(page([local]));
  render(<QueryClientProvider client={new QueryClient()}>
    <ComputerPanel row={{ ...workstation, computer_key: "host-1-cGMtdGVzdA" }} logons
      logonParams="period=7d" onClose={() => {}} timeZone="UTC"/>
  </QueryClientProvider>);
  const table = await screen.findByRole("table");
  expect(within(table).queryByRole("columnheader", { name: t("reports.v2.ad.computer-logons.detail.columns.source.label") })).toBeNull();
  expect(within(table).getAllByRole("row")).toHaveLength(2);
});

it("keeps individual observations selected by row ID through paging and resets on a new result", async () => {
  const first = observation("101", "53");
  const second = observation("102", "37");
  const unlinked = observation("103", "19", null);
  const newFirst = observation("104", "58", 82);
  const request = vi.spyOn(api, "reportV2Detail")
    .mockResolvedValueOnce(page([first, second], "next-observations"))
    .mockResolvedValueOnce(page([unlinked]))
    .mockResolvedValueOnce(page([newFirst, unlinked]));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const panel = (params: string) => <QueryClientProvider client={client}>
    <ComputerPanel row={workstation} logons logonParams={params} onClose={() => {}} timeZone="UTC"/>
  </QueryClientProvider>;
  const view = render(panel("user=test&period=7d"));

  await screen.findByRole("table", { name: t("reports.computers.observations") });
  const rows = () => within(screen.getByRole("table", { name: t("reports.computers.observations") })).getAllByRole("row").slice(1);
  const rowTimes = () => rows().map((row) => within(row).getAllByRole("cell")[0].textContent);
  const expectTimes = (...items: typeof first[]) => expect(rowTimes())
    .toEqual(items.map((item) => formatDateTime(item.observed_at_utc, true, "UTC")));
  const expectSelected = (index: number) => expect(rows().map((row) => row.getAttribute("aria-selected")))
    .toEqual(rows().map((_, i) => String(i === index)));

  expectTimes(first, second);
  expectSelected(0);
  fireEvent.keyDown(rows()[1], { key: "Enter" });
  expectSelected(1);
  expect(screen.getByRole("link", { name: t("reports.computers.open_event") }).getAttribute("href")?.split("?")[0])
    .toBe("/app/events/81");
  expect(screen.queryByText("#81")).toBeNull();

  fireEvent.click(screen.getByRole("button", { name: t("table.loadMore") }));
  await waitFor(() => expect(rows()).toHaveLength(3));
  expectTimes(first, second, unlinked);
  expectSelected(1);
  expect(request.mock.calls[1][2]?.get("cursor")).toBe("next-observations");
  expect(request.mock.calls[1][2]?.get("user")).toBe("test");
  expect(request.mock.calls[1][2]?.get("period")).toBe("7d");

  fireEvent.click(rows()[2]);
  expectSelected(2);
  expect(within(rows()[2]).queryByRole("link")).toBeNull();
  expect(screen.queryByRole("link", { name: t("reports.computers.open_event") })).toBeNull();

  view.rerender(panel("user=other&period=30d"));
  await screen.findByText(formatDateTime(newFirst.observed_at_utc, true, "UTC"), { selector: "td" });
  expectTimes(newFirst, unlinked);
  expectSelected(0);
  expect(request.mock.calls[2][2]?.has("cursor")).toBe(false);
});

it("keeps identical observations on separate selectable rows for an older response", async () => {
  const legacy = { observed_at_utc: "2026-01-12T10:53:00Z", user_name: "EXAMPLE\\test", source_event_id: 81 };
  vi.spyOn(api, "reportV2Detail").mockResolvedValue(page([legacy, { ...legacy }]));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}>
    <ComputerPanel row={workstation} logons logonParams="" onClose={() => {}} timeZone="UTC"/>
  </QueryClientProvider>);
  const table = await screen.findByRole("table", { name: t("reports.computers.observations") });
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows).toHaveLength(2);
  fireEvent.click(rows[1]);
  expect(rows.map((row) => row.getAttribute("aria-selected"))).toEqual(["false", "true"]);
});

it("shows grouped stored logons and pages them independently of the computer list", async () => {
  const grouped = { ...observation("101", "53"), logon_type: "3", source: "SOURCE-PC / 192.0.2.21", repeat_count: 4 };
  const next = { ...observation("102", "37", 82), user_name: "EXAMPLE\\second" };
  const request = vi.spyOn(api, "reportV2Detail").mockImplementation(async (_key, _row, params) =>
    params.get("cursor") ? page([next]) : page([grouped], "next-group"));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}>
    <ComputerPanel row={{ ...workstation, computer_key: "host-1-cGMtdGVzdA" }} logons
      logonParams="period=custom&from=2026-01-01T00%3A00%3A00Z&to=2026-01-15T00%3A00%3A00Z&service_logons=yes&limit=100"
      onClose={() => {}} timeZone="UTC"/>
  </QueryClientProvider>);
  const table = await screen.findByRole("table");
  const row = within(table).getAllByRole("row")[1];
  expect(row.textContent).toContain("SOURCE-PC");
  expect(row.textContent).toContain("192.0.2.21");
  expect(row.textContent).toContain("×4");
  expect(within(row).getByRole("link", { name: new RegExp(t("reports.computers.open_event")) }).getAttribute("href")).toMatch(/^\/app\/events\/81(?:\?|$)/);
  expect(within(row).queryByText("#81")).toBeNull();
  expect(request.mock.calls[0][1]).toBe("host-1-cGMtdGVzdA");
  expect(request.mock.calls[0][2].get("limit")).toBe("50");
  fireEvent.click(screen.getByRole("button", { name: t("table.next") }));
  await within(table).findByText("EXAMPLE\\second");
  expect(within(table).queryByText("EXAMPLE\\test")).toBeNull();
  const nextParams = request.mock.calls[1][2];
  expect(nextParams.get("cursor")).toBe("next-group");
  expect(nextParams.get("service_logons")).toBe("yes");
  expect(nextParams.get("from")).toBe("2026-01-01T00:00:00Z");
});
