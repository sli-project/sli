/** @vitest-environment jsdom */
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, type EventItem, type InvestigationCase } from "../api/client";
import { localeRuntime, setLocale, t } from "../i18n";
import { InvestigationCasePage } from "./case-page";

vi.mock("./App", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./App")>()),
  useTimeZone: () => ({ timeZone: "UTC" }),
}));

const evidence: InvestigationCase["events"] = [
  { event_db_id: 101, relation_status: "confirmed", added_by: "synthetic", added_at: "2026-10-05T12:00:00Z" },
  { event_db_id: 102, relation_status: "confirmed", added_by: "synthetic", added_at: "2026-10-05T11:00:00Z" },
  { event_db_id: 103, relation_status: "excluded", added_by: "synthetic", added_at: "2026-10-05T10:00:00Z" },
  { event_db_id: 104, relation_status: "confirmed", added_by: "synthetic", added_at: "2026-10-05T09:00:00Z" },
  { event_db_id: 105, relation_status: "confirmed", added_by: "synthetic", added_at: "2026-10-05T08:00:00Z" },
  { event_db_id: 106, relation_status: "confirmed", added_by: "synthetic", added_at: "2026-10-05T07:00:00Z" },
  { event_db_id: 107, relation_status: "confirmed", added_by: "synthetic", added_at: "2026-10-05T06:00:00Z" },
];
const events: EventItem[] = [
  { event_db_id: 101, event_id: 1, label: "Synthetic low", final_risk: "low", time_created_utc: "2026-10-01T10:00:00Z" },
  { event_db_id: 102, event_id: 2, label: "Synthetic critical", final_risk: "critical", time_created_utc: "2026-10-05T10:00:00Z" },
  { event_db_id: 103, event_id: 3, label: "Synthetic high", final_risk: "high", time_created_utc: "2026-10-04T10:00:00Z" },
  { event_db_id: 104, event_id: 4, label: "Synthetic medium", final_risk: "medium", time_created_utc: "2026-10-03T10:00:00Z" },
  { event_db_id: 105, event_id: 5, label: "Synthetic unknown", time_created_utc: null },
  { event_db_id: 106, event_id: 6, label: "Synthetic unrecognized", final_risk: "unrecognized", time_created_utc: "invalid" },
  { event_db_id: 107, event_id: 7, label: "Synthetic info", final_risk: "info", time_created_utc: "2026-10-02T10:00:00Z" },
];
const caseData: InvestigationCase = {
  id: 7, title: "Synthetic case", status: "new", created_by: "synthetic", owner: null,
  created_at: "2026-10-05T12:00:00Z", updated_at: "2026-10-05T12:00:00Z",
  events: evidence, notes: [], audit: [], evidence_refs: [], evidence_refs_state: "available",
};

beforeEach(() => { vi.spyOn(window, "scrollTo").mockImplementation(() => undefined); });

afterEach(() => {
  cleanup();
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  vi.restoreAllMocks();
});

async function renderCase(search = "", eventItems = events, role = "viewer", data = caseData) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], { effective_role: role });
  client.setQueryData(["investigation-case", "7", Number(new URLSearchParams(search).get("event_db_id")) || null, undefined, undefined], data);
  client.setQueryData(["investigation-case", "8", Number(new URLSearchParams(search).get("event_db_id")) || null, undefined, undefined], { ...caseData, id: 8 });
  client.setQueryData(["events-batch", evidence.map((item) => item.event_db_id)], { items: eventItems });
  const root = createRootRoute();
  const detail = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: InvestigationCasePage });
  const list = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([detail, list]), basepath: "/app",
    history: createMemoryHistory({ initialEntries: [`/app/investigations/7${search}`] }) });
  await router.load();
  render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  await screen.findByRole("heading", { name: caseData.title });
  return { client, router };
}

function evidenceTable() { return screen.getByRole("table", { name: t("investigations.case.case_evidence") }); }

it.each(["ru", "en"] as const)("renders lifecycle options in %s even when the page was imported in Russian", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  await renderCase("", events, "admin");
  const select = await screen.findByRole("combobox", { name: t("investigations.case.status") });
  for (const status of ["new", "active", "review", "confirmed", "closed"] as const) {
    expect(within(select).getByRole("option", { name: t(`investigations.caseStatus.${status}`) }).getAttribute("value")).toBe(status);
  }
});

it("shows the same short case number as the case list", async () => {
  await renderCase();
  expect(screen.getByText("INV-0000007")).toBeTruthy();
  expect(screen.queryByText("CASE-7")).toBeNull();
});

it("keeps the short case number while translating coded evidence in English", async () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  const eventItems = events.map((event) => event.event_db_id === 101 ? { ...event, semantics: {
    title_code: "Security:Microsoft-Windows-Security-Auditing:4719.title", title: "Синтетический заголовок",
  } } : event);
  await renderCase("?event_db_id=101", eventItems);
  expect(screen.getByText("INV-0000007")).toBeTruthy();
  expect(within(evidenceTable()).getByText("Audit policy changed")).toBeTruthy();
  expect(within(selectedSection()).getByRole("heading", { name: "Audit policy changed" })).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.nodes_without_links") }));
  expect(screen.getByRole("button", { name: /Audit policy changed/ })).toBeTruthy();
  expect(screen.queryByText("Синтетический заголовок")).toBeNull();
});
function visibleIds() {
  return within(evidenceTable()).getAllByRole("row").slice(1).map((row) => Number(row.textContent?.match(/DB (\d+)/)?.[1]));
}
function selectedSection() { return screen.getByRole("region", { name: t("investigations.case.selected_event") }); }
function expectSelected(id: number) {
  expect(within(selectedSection()).getByRole("link", { name: t("investigations.case.open_full_event") }).getAttribute("href")).toContain(`/events/${id}`);
}

it.each([
  ["critical", [102]], ["high", [102, 103]], ["medium", [102, 103, 104]], ["low", [102, 103, 104, 101]],
  ["unknown", [106, 105]], ["", [102, 103, 104, 107, 101, 106, 105]],
] as const)("applies minimum risk %s with unknown classes separate", async (minimum, expected) => {
  await renderCase();
  await userEvent.selectOptions(screen.getByLabelText(t("investigations.case.minimum_risk")), minimum);
  expect(visibleIds()).toEqual(expected);
});

it("combines the risk threshold with the evidence relation filter", async () => {
  await renderCase();
  await userEvent.selectOptions(screen.getByLabelText(t("investigations.case.minimum_risk")), "high");
  await userEvent.selectOptions(screen.getByLabelText(t("investigations.case.relation_status")), "confirmed");
  expect(visibleIds()).toEqual([102]);
});

it("selects saved URL evidence instead of the first added proof", async () => {
  await renderCase("?event_db_id=103");
  expectSelected(103);
  expect(evidenceTable().querySelector('tr[aria-selected="true"]')?.textContent).toContain("DB 103");
  expect(screen.queryByText(t("investigations.case.anchor_not_saved", { id: 103 }))).toBeNull();
});

it("explains when the URL anchor is absent from the saved case", async () => {
  await renderCase("?event_db_id=999");
  expect(screen.getByText(t("investigations.case.anchor_not_saved", { id: 999 }))).toBeTruthy();
  expectSelected(101);
});

it("keeps an intentional clear across filters, views and case refresh, and allows reselection", async () => {
  const { client } = await renderCase("?event_db_id=103");
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.clear_event_selection") }));
  const expectCleared = () => {
    expect(within(selectedSection()).queryByRole("link")).toBeNull();
    expect(evidenceTable().querySelector('tr[aria-selected="true"]')).toBeNull();
    expect(screen.getByText(t("investigations.case.select_evidence_in_the_timeline_or_nodes"))).toBeTruthy();
  };
  expectCleared();
  await act(async () => { client.setQueryData(["investigation-case", "7", null, undefined, undefined], { ...caseData, updated_at: "2026-10-05T13:00:00Z" }); });
  await userEvent.selectOptions(screen.getByLabelText(t("investigations.case.minimum_risk")), "high");
  await userEvent.selectOptions(screen.getByLabelText(t("investigations.case.evidence_order")), "added_at");
  expectCleared();
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.nodes_without_links") }));
  expect(within(selectedSection()).queryByRole("link")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.timeline") }));
  expectCleared();
  await userEvent.click(within(evidenceTable()).getByText("Synthetic critical"));
  expectSelected(102);
});

it("resets the selection on a new URL anchor or another case", async () => {
  const { router, client } = await renderCase("?event_db_id=103");
  client.setQueryData(["investigation-case", "7", 102, undefined, undefined], caseData);
  client.setQueryData(["investigation-case", "8", 102, undefined, undefined], { ...caseData, id: 8 });
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.clear_event_selection") }));
  await act(async () => { await router.navigate({ to: "/investigations/$investigationId", params: { investigationId: "7" }, search: { event_db_id: 102 } }); });
  await waitFor(() => expectSelected(102));
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.clear_event_selection") }));
  await act(async () => { await router.navigate({ to: "/investigations/$investigationId", params: { investigationId: "8" }, search: { event_db_id: 102 } }); });
  await waitFor(() => expectSelected(102));
});

it("orders by event time by default and offers addition order separately", async () => {
  await renderCase();
  expect(visibleIds()).toEqual([102, 103, 104, 107, 101, 106, 105]);
  await userEvent.selectOptions(screen.getByLabelText(t("investigations.case.evidence_order")), "added_at");
  expect(visibleIds()).toEqual([101, 102, 103, 104, 105, 106, 107]);
  await userEvent.selectOptions(screen.getByLabelText(t("investigations.case.evidence_order")), "event_time");
  expect(visibleIds()).toEqual([102, 103, 104, 107, 101, 106, 105]);
});

it.each(["ru", "en"] as const)("names the unlinked node view honestly in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  await renderCase();
  expect(screen.queryByRole("button", { name: t("investigations.case.graph") })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.nodes_without_links") }));
  const nodes = screen.getByRole("group", { name: t("investigations.case.investigation_evidence_without_causal_links") });
  expect(within(nodes).getAllByRole("button")).toHaveLength(events.length);
  expect(within(nodes).getByText(t("investigations.case.the_order_of_adding_evidence_does_not_prove_causation_edges_"))).toBeTruthy();
  await userEvent.click(within(nodes).getByRole("button", { name: /Synthetic critical/ }));
  expectSelected(102);
});


it("provides continuation instead of silently dropping saved evidence", async () => {
  const { client } = await renderCase();
  act(() => client.setQueryData(["investigation-case", "7", null, undefined, undefined], {
    ...caseData, evidence_page_size: 100, events_total: 701, events_next_cursor: 101,
  }));
  vi.spyOn(api, "investigationCase").mockResolvedValue({ ...caseData, events: [{ ...evidence[0], event_db_id: 1 }] });
  await userEvent.click(await screen.findByRole("button", { name: "Следующая страница событий" }));
  await waitFor(() => expect(api.investigationCase).toHaveBeenCalledWith(7, expect.objectContaining({ eventAfter: 101 })));
});


it("loads the exact saved anchor beyond the current page in its own bounded batch", async () => {
  const anchor = { ...evidence[0], event_db_id: 1 };
  const metadata = { event_db_id: 1, event_id: 900, label: "Off-page anchor" };
  const pageEvents = Array.from({ length: 100 }, (_, index) => ({ ...evidence[0], event_db_id: 200 + index }));
  vi.spyOn(api, "eventsBatch").mockImplementation(async (ids) => ({ api_version: "v1", items: ids.map((id) => id === 1 ? metadata : { event_db_id: id, event_id: id }), requested_event_db_ids: [...ids], missing_event_db_ids: [], limit: 100 }));
  await renderCase("?event_db_id=1", events, "viewer", { ...caseData, events: pageEvents, anchor_event: anchor, events_total: 701, evidence_page_size: 100, events_next_cursor: 200 });
  await waitFor(() => expect(api.eventsBatch).toHaveBeenCalledWith([1]));
  expect(vi.mocked(api.eventsBatch).mock.calls.every(([ids]) => ids.length <= 100)).toBe(true);
  expect(vi.mocked(api.eventsBatch).mock.calls.some(([ids]) => ids.length === 100)).toBe(true);
  expectSelected(1);
  expect(await within(selectedSection()).findByRole("heading", { name: "Off-page anchor" })).toBeTruthy();
  expect(within(evidenceTable()).queryByText("Off-page anchor")).toBeNull();
  expect(screen.queryByText(t("investigations.case.anchor_not_saved", { id: 1 }))).toBeNull();
});

it("keeps a later page failure explicit and offers retry and restart", async () => {
  await renderCase("", events, "viewer", { ...caseData, events_total: 701, evidence_page_size: 100, events_next_cursor: 101 });
  vi.spyOn(api, "investigationCase").mockRejectedValue(new Error("synthetic outage"));
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.next_events") }));
  expect(await screen.findByRole("button", { name: t("investigations.case.retry_page") })).toBeTruthy();
  expect(screen.queryByRole("table", { name: t("investigations.case.case_evidence") })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.restart_pages") }));
  expect(await screen.findByRole("table", { name: t("investigations.case.case_evidence") })).toBeTruthy();
});

it("states that filters and nodes cover the current page, not all saved events", async () => {
  await renderCase("", events, "viewer", { ...caseData, events_total: 701, evidence_page_size: 100, events_next_cursor: 101 });
  expect(screen.getByText(t("investigations.case.page_scope", { shown: 7, total: 701 }))).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.nodes_without_links") }));
  expect(screen.getByText(t("investigations.case.page_scope", { shown: 7, total: 701 }))).toBeTruthy();
});


it("does not turn denied off-page anchor metadata into an empty result", async () => {
  const { ApiResponseError } = await import("../api/client");
  vi.spyOn(api, "eventsBatch").mockRejectedValue(new ApiResponseError(403, "forbidden", "denied"));
  await renderCase("?event_db_id=1", events, "viewer", { ...caseData, anchor_event: { ...evidence[0], event_db_id: 1 } });
  expect(await within(selectedSection()).findByText(t("investigations.case.no_permission_to_view_the_evidence_context"))).toBeTruthy();
  expect(screen.queryByText(t("investigations.case.anchor_not_saved", { id: 1 }))).toBeNull();
});

it("continues authorized typed references without changing the event cursor", async () => {
  await renderCase("", events, "viewer", { ...caseData, evidence_refs_total: 501, evidence_refs_next_cursor: "opaque-reference-cursor" });
  vi.spyOn(api, "investigationCase").mockResolvedValue(caseData);
  await userEvent.click(screen.getByRole("button", { name: t("investigations.case.next_refs") }));
  await waitFor(() => expect(api.investigationCase).toHaveBeenCalledWith(7, { eventAfter: undefined, referenceAfter: "opaque-reference-cursor", anchorEventId: undefined }));
});
