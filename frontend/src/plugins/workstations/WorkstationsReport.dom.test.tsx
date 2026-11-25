// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import definitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import * as app from "../../app/App";
import { localeRuntime, setLocale, t } from "../../i18n";
import { WorkstationsPage } from "./route";
import { WORKSTATIONS_KEY, type StationDetailResult } from "./model";

const definition = { ...definitions.find(item => item.key === WORKSTATIONS_KEY), filter_options: {} } as unknown as ReportDefinitionDto;
const source = "00000000-0000-4000-8000-000000000001";
const stationId = "00000000-0000-4000-8000-000000000002";
const from = "2026-11-25T09:14:23.456Z", to = "2026-11-25T11:18:29.789Z";
const requests: URL[] = [], invalidRequests: string[] = [];
let revision = "initial", denied = false, detailMode: "normal" | "denied" | "events_denied" | "malformed" = "normal";
let client: QueryClient;
const station = (index = 0) => ({ station_id: index ? `00000000-0000-4000-8000-${String(index + 2).padStart(12, "0")}` : stationId,
  agent_key: index ? `00000000-0000-4000-8000-${String(index + 2).padStart(12, "0")}` : stationId,
  transport_agent_id: "00000000-0000-4000-8000-000000000003", source_instance_id: index ? `10000000-0000-4000-8000-${String(index).padStart(12, "0")}` : source,
  display_name: `WS-WORKSPACE-${String(index + 1).padStart(3, "0")}`, host_name: `WS-WORKSPACE-${String(index + 1).padStart(3, "0")}`,
  domain_id: 11, domain_name: "synthetic.invalid", server_id: 5, operating_system: "Windows 11", operating_system_version: "26100",
  metadata_observed_at: "2026-11-25T08:00:00Z", agent_status: "active", last_seen: "2026-11-25T09:05:00Z",
  policy_revision: 4, applied_policy_revision: 4, collection_state: "enabled", journal_available: true,
  profile: { state: "supported", event_ids: [4624, 4625, 1102, 4698, 4732, 4733, 5001, 5010, 5012, 7036, 7040, 7045], channels: ["Security", "System", "Microsoft-Windows-Windows Defender/Operational"] },
});
const result = (overrides: Partial<ReportResultDto> = {}): ReportResultDto => ({ contract_id: "sli.report-result.v2", report_key: WORKSTATIONS_KEY,
  state: "ok", items: [], has_more: false, next_cursor: null, filtered_count: 205, metrics: [], series: {}, coverage: {},
  filter_options: {}, limitations: [], window: { from_utc: from, to_utc_exclusive: to }, collections: { paging: [{ start: 1, has_previous: false, previous_cursor: null }] }, ...overrides });
const events = [
  { id: 101, event_id: 4624, title_text: "Synthetic grouped sign-ins", participant: "SYNTHETIC\\alice", channel: "Security", journal_result: "success",
    time_created_utc: "2026-11-25T10:00:00Z", first_seen_utc: "2026-11-25T08:00:00Z", last_seen_utc: "2026-11-25T12:00:00Z", event_count: 39,
    journal_expandable: true, journal_evidence_available: true },
  { id: 102, event_id: 1102, title_text: "Synthetic audit cleared", participant: "SYNTHETIC\\operator", channel: "Security",
    time_created_utc: "2026-11-25T10:10:00Z", event_count: 1, journal_expandable: false, journal_evidence_available: true,
    journal_finding_id: 7, journal_severity: "high" },
];
const detailResult = (): StationDetailResult => ({ ...result({ items: [station()], filtered_count: 1,
  ...(detailMode === "denied" ? { access: { allowed: false } } : {}) }), detail: {
  station: detailMode === "malformed" ? { station_id: stationId } : station(),
  events: { state: detailMode === "events_denied" ? "denied" : "ok", items: events, filtered_count: 2, journal_event_count: 40, has_more: true,
    next_cursor: "bound-next-event-page", window: { from_utc: from, to_utc_exclusive: to } },
  related: { journal: { allowed: detailMode !== "events_denied", params: { domain: 11, server: "WS-WORKSPACE-001", source_instance_id: source,
    source_plugin: "sli.workstations", period: "custom", from, to, tz: "UTC", collapse: "on" } }, problems: { allowed: true } },
} });

beforeEach(() => {
  denied = false; detailMode = "normal"; revision = "initial"; requests.length = 0; invalidRequests.length = 0;
  localStorage.clear();
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  vi.spyOn(app, "useEffectiveAccess").mockImplementation(() => ({ subject: { type: "session", id: 7 }, evaluated_at_utc: revision,
    capabilities: ["workstations.read"], reports: [{ report_key: WORKSTATIONS_KEY, allowed: !denied }] }) as unknown as ReturnType<typeof app.useEffectiveAccess>);
  vi.spyOn(app, "useTimeZone").mockReturnValue({ timeZone: "UTC", setTimeZone: vi.fn() } as ReturnType<typeof app.useTimeZone>);
  const query = new URLSearchParams({ nav_view: "overview", domain_id: "11", domain: "22", search: "WS-", collection: "enabled",
    period: "custom", from, to, limit: "50" });
  window.history.replaceState(null, "", `/app/report/workstations.overview?${query}`);
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), window.location.origin); requests.push(url);
    if (!url.pathname.includes("/data") && !url.pathname.includes("/detail")) return new Response(JSON.stringify({ ...definition, access: { allowed: !denied } }));
    const allowed = new Set([...definition.params.map(param => param.key), "from", "to", "tz", "limit", "cursor"]);
    const unknown = [...url.searchParams.keys()].filter(key => !allowed.has(key));
    if (unknown.length) { invalidRequests.push(...unknown); return new Response(JSON.stringify({ error: "report_parameter_unknown" }), { status: 400 }); }
    if (denied) return new Response(JSON.stringify({ error: "workstation_access_denied" }), { status: 403 });
    if (url.pathname.includes("/detail")) return new Response(JSON.stringify(detailResult()));
    const total = url.searchParams.get("source_instance_id") === source ? 1 : 205;
    const limit = Number(url.searchParams.get("limit")), offset = url.searchParams.has("cursor") ? 200 : 0;
    const items = Array.from({ length: Math.max(0, Math.min(limit, total - offset)) }, (_, index) => station(index + offset));
    return new Response(JSON.stringify(result({ items, filtered_count: total, has_more: offset + items.length < total, next_cursor: "bound-fleet-page",
      collections: { paging: [{ start: offset + 1, has_previous: offset > 0, previous_cursor: null }] } })));
  }));
});
afterEach(() => { cleanup(); client?.clear(); setLocale("ru"); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={client}><WorkstationsPage/></QueryClientProvider>);
  return { ...view, refresh: () => view.rerender(<QueryClientProvider client={client}><WorkstationsPage/></QueryClientProvider>) };
}

it.each(["ru", "en"] as const)("uses the real registry for fleet → full station → grouped fact → permitted evidence → collection → exact return (%s)", async locale => {
  setLocale(locale); mount();
  await screen.findByRole("table", { name: t("workstations.overview.stations") });
  fireEvent.change(screen.getByLabelText(t("table.rowsPerPage")), { target: { value: "200" } });
  await waitFor(() => expect(within(screen.getByRole("table", { name: t("workstations.overview.stations") })).getAllByRole("row")).toHaveLength(201));
  expect(requests.filter(url => url.pathname.endsWith("/data")).at(-1)?.searchParams.get("limit")).toBe("200");
  expect(screen.queryByRole("region", { name: t("reports.summaryAria") })).toBeNull();
  expect(screen.queryByText(t("state.partial.title"))).toBeNull();
  expect(screen.queryByRole("columnheader", { name: t("workstations.workspace.collection") })).toBeNull();
  expect(screen.getAllByRole("img", { name: t("workstations.workspace.collection_enabled") })[0].getAttribute("title")).toBe(t("workstations.workspace.collection_enabled"));
  const fleet = new URLSearchParams(window.location.search); fleet.set("source_instance_id", source);
  window.history.pushState(null, "", `${window.location.pathname}?${fleet}`); window.dispatchEvent(new PopStateEvent("popstate"));
  await waitFor(() => expect(within(screen.getByRole("table", { name: t("workstations.overview.stations") })).getAllByRole("row")).toHaveLength(2));
  fireEvent.click(screen.getByRole("link", { name: "WS-WORKSPACE-001" }));
  await screen.findByRole("table", { name: t("workstations.workspace.station_events") });
  expect(screen.queryByRole("dialog")).toBeNull();
  fireEvent.click(screen.getByRole("link", { name: t("workstations.workspace.event_4624") }));
  const facts = await screen.findByRole("region", { name: t("workstations.workspace.event_facts") });
  expect(within(facts).getByRole("heading", { name: t("workstations.workspace.event_4624") }).getAttribute("title")).toBe("Synthetic grouped sign-ins");
  expect(within(facts).getByText("39")).toBeTruthy();
  expect(within(facts).getByText(t("workstations.workspace.saved_group"))).toBeTruthy();
  expect(within(facts).getByText(t("workstations.workspace.group_boundary"))).toBeTruthy();
  expect(within(facts).queryByRole("link", { name: t("workstations.workspace.original") })).toBeNull();
  const groupLink = new URL(within(facts).getByRole("link", { name: t("workstations.workspace.group_journal") }).getAttribute("href")!, window.location.origin);
  expect(groupLink.searchParams.get("source_instance_id")).toBe(source); expect(groupLink.searchParams.get("expand")).toBe("101");
  fireEvent.click(screen.getByRole("button", { name: t("workstations.workspace.back_events") }));
  fireEvent.click(await screen.findByRole("link", { name: t("workstations.workspace.event_1102") }));
  const evidence = new URL(screen.getByRole("link", { name: t("workstations.workspace.original") }).getAttribute("href")!, window.location.origin);
  expect(evidence.pathname).toBe("/app/events/102");
  expect(evidence.searchParams.get("return_to")).toBe(window.location.pathname + window.location.search);
  expect(screen.getByRole("link", { name: new RegExp(t("workstations.workspace.finding", { id: "7" })) }).getAttribute("href")).toContain("id=7");
  fireEvent.click(screen.getByRole("tab", { name: t("workstations.workspace.collection_tab") }));
  expect(await screen.findByRole("table", { name: t("workstations.workspace.profile_events") })).toBeTruthy();
  expect(screen.getByText(source)).toBeTruthy();
  expect(screen.getByText(t("workstations.workspace.profile_scope"))).toBeTruthy();
  fireEvent.click(screen.getByRole("link", { name: t("workstations.workspace.back_fleet") }));
  await screen.findByRole("table", { name: t("workstations.overview.stations") });
  const returned = new URLSearchParams(window.location.search);
  for (const [key, value] of fleet) expect(returned.get(key)).toBe(value);
  expect(returned.has("station")).toBe(false);
  expect(returned.get("selected_station")).toBe(stationId);
  expect(invalidRequests).toEqual([]);
  const detailCalls = requests.filter(url => url.pathname.includes("/detail"));
  expect(detailCalls.length).toBeGreaterThan(0);
  for (const url of detailCalls) {
    expect(url.searchParams.get("domain")).toBe("11"); expect(url.searchParams.get("source_instance_id")).toBe(source);
    expect(url.searchParams.get("from")).toBe(from); expect(url.searchParams.get("to")).toBe(to);
    expect(url.searchParams.has("search")).toBe(false); expect(url.searchParams.has("collection")).toBe(false);
  }
});

it("opens a direct station URL independently of the fleet page and resets only event paging when its size changes", async () => {
  const query = new URLSearchParams(window.location.search);
  query.set("station", stationId); query.set("cursor", "bound-fleet-page"); query.set("event_cursor", "bound-event-page");
  query.set("event_history", "[null]"); query.set("event_page", "1"); query.set("event_limit", "25");
  window.history.replaceState(null, "", `/app/report/workstations.overview?${query}`);
  mount(); await screen.findByRole("table", { name: t("workstations.workspace.station_events") });
  expect(requests.some(url => url.pathname.endsWith("/data"))).toBe(false);
  expect(requests.find(url => url.pathname.includes("/detail"))?.searchParams.get("event_cursor")).toBe("bound-event-page");
  fireEvent.change(screen.getByLabelText(t("table.rowsPerPage")), { target: { value: "200" } });
  await waitFor(() => expect(requests.filter(url => url.pathname.includes("/detail")).at(-1)?.searchParams.get("event_limit")).toBe("200"));
  const last = requests.filter(url => url.pathname.includes("/detail")).at(-1)!;
  expect(last.searchParams.has("event_cursor")).toBe(false); expect(last.searchParams.has("cursor")).toBe(false);
  expect(new URLSearchParams(window.location.search).get("cursor")).toBe("bound-fleet-page");
  expect(invalidRequests).toEqual([]);
});

it("restores the original fleet time and cursor after applying a different station event window", async () => {
  mount(); fireEvent.click(await screen.findByRole("link", { name: "WS-WORKSPACE-001" }));
  await screen.findByRole("table", { name: t("workstations.workspace.station_events") });
  fireEvent.change(screen.getByLabelText(t("period.from")), { target: { value: "2026-11-25T09:30:00.123" } });
  fireEvent.click(screen.getByRole("button", { name: t("filters.apply") }));
  await waitFor(() => expect(new URLSearchParams(window.location.search).get("from")).toBe("2026-11-25T09:30:00.123Z"));
  fireEvent.click(screen.getByRole("link", { name: t("workstations.workspace.back_fleet") }));
  await screen.findByRole("table", { name: t("workstations.overview.stations") });
  expect(new URLSearchParams(window.location.search).get("from")).toBe(from);
  expect(new URLSearchParams(window.location.search).get("to")).toBe(to);
});

it("clears opened station data when the effective session loses access", async () => {
  const view = mount(); fireEvent.click(await screen.findByRole("link", { name: "WS-WORKSPACE-001" }));
  await screen.findByRole("table", { name: t("workstations.workspace.station_events") });
  denied = true; revision = "revoked"; view.refresh();
  await waitFor(() => expect(screen.queryByText("Synthetic audit cleared")).toBeNull());
  expect(screen.queryByText("SYNTHETIC\\alice")).toBeNull();
  expect(screen.queryByRole("heading", { name: "WS-WORKSPACE-001" })).toBeNull();
});

it.each(["denied", "malformed"] as const)("fails closed on a %s station detail result", async mode => {
  detailMode = mode; mount(); fireEvent.click(await screen.findByRole("link", { name: "WS-WORKSPACE-001" }));
  await screen.findByRole("alert");
  expect(screen.queryByText("Synthetic audit cleared")).toBeNull();
  expect(screen.queryByRole("table", { name: t("workstations.workspace.station_events") })).toBeNull();
});

it("keeps collection metadata available while independently denying the journal branch", async () => {
  detailMode = "events_denied"; mount(); fireEvent.click(await screen.findByRole("link", { name: "WS-WORKSPACE-001" }));
  expect(await screen.findByText(t("workstations.workspace.events_denied"))).toBeTruthy();
  expect(screen.queryByText("Synthetic grouped sign-ins")).toBeNull();
  expect(screen.queryByRole("link", { name: t("workstations.workspace.open_journal") })).toBeNull();
  fireEvent.click(screen.getByRole("tab", { name: t("workstations.workspace.collection_tab") }));
  expect(await screen.findByText(source)).toBeTruthy();
});
