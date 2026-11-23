// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportResultDto } from "../../api/report-v2-types";
import { formatDateTime } from "../../design-system/format";
import { t } from "../../i18n";
import { ComputerPanel } from "./ComputersPanel";

vi.mock("../App", () => ({ useEffectiveAccess: () => null }));
vi.mock("../../shared/time-zone", () => ({ useTimeZone: () => ({ timeZone: "UTC" }) }));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const workstation = { entity_id: 7, display_name: "PC-TEST", computer_type: "workstation" };
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
    <ComputerPanel row={workstation} logons logonParams={params} changes={[]} canCompare={false} onClose={() => {}} timeZone="UTC"/>
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
  expect(rows().map((row) => within(row).getByRole("link").getAttribute("href")?.split("?")[0]))
    .toEqual(["/app/events/81", "/app/events/81"]);

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
    <ComputerPanel row={workstation} logons logonParams="" changes={[]} canCompare={false} onClose={() => {}} timeZone="UTC"/>
  </QueryClientProvider>);
  const table = await screen.findByRole("table", { name: t("reports.computers.observations") });
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows).toHaveLength(2);
  fireEvent.click(rows[1]);
  expect(rows.map((row) => row.getAttribute("aria-selected"))).toEqual(["false", "true"]);
});
