import { expect, it } from "vitest";
import definitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { appliedFilters, eventHistory, eventRows, evidenceHref, exactWindow, filterValues, fleetReturnHref,
  initialSearch, journalHref, pageSize, paging, requestParams, stationRows, type Station, type StationDetailResult } from "./model";

const definition = definitions.find(item => item.key === "workstations.overview") as unknown as ReportDefinitionDto;
const source = "00000000-0000-4000-8000-000000000001";
const windowQuery = "period=custom&from=2026-11-25T09%3A14%3A23.456Z&to=2026-11-25T11%3A18%3A29.789Z";

it("uses the shipped native registry and sends the selected size rather than slicing a loaded preview", () => {
  expect(definition.limits.max).toBe(200);
  for (const size of [25, 50, 100, 200]) {
    expect(requestParams(new URLSearchParams(`${windowQuery}&limit=${size}`), "UTC", definition)?.get("limit")).toBe(String(size));
    expect(pageSize(size)).toBe(size);
  }
  expect(pageSize(200, 50)).toBe(50);
  expect(pageSize("unbounded")).toBe(50);
  expect(paging([{ start: 201, has_previous: true, previous_cursor: "bound-cursor" }])).toEqual({ start: 201, hasPrevious: true, previousCursor: "bound-cursor" });
});

it("keeps browser context out of native list and detail requests while preserving exact scope and independent cursors", () => {
  const search = new URLSearchParams(`${windowQuery}&domain_id=11&domain=22&source_instance_id=${source}&search=WS-&collection=enabled&limit=200&cursor=fleet-page`);
  for (const [key, value] of Object.entries({ station: source, station_tab: "events", station_return: "/app/report/workstations.overview?search=WS-",
    event: "101", event_cursor: "event-page", event_history: "[null]", event_page: "1", event_limit: "100", nav_view: "overview", ws_preset: "7d", view: "groups" })) search.set(key, value);
  const before = search.toString();
  const list = requestParams(search, "UTC", definition)!, detail = requestParams(search, "UTC", definition, true)!;
  const allowed = new Set([...definition.params.map(param => param.key), "from", "to", "tz", "limit", "cursor"]);
  for (const params of [list, detail]) {
    expect([...params.keys()].every(key => allowed.has(key))).toBe(true);
    expect(params.get("domain")).toBe("11");
    expect(params.get("source_instance_id")).toBe(source);
    expect(params.get("from")).toBe("2026-11-25T09:14:23.456Z");
    expect(params.get("to")).toBe("2026-11-25T11:18:29.789Z");
    for (const key of ["domain_id", "station", "station_tab", "station_return", "event", "event_history", "event_page", "nav_view", "ws_preset"]) expect(params.has(key)).toBe(false);
  }
  expect(list.get("cursor")).toBe("fleet-page"); expect(list.get("search")).toBe("WS-"); expect(list.has("event_cursor")).toBe(false);
  expect(detail.get("event_cursor")).toBe("event-page"); expect(detail.get("event_limit")).toBe("100"); expect(detail.get("view")).toBe("groups");
  expect(detail.has("cursor")).toBe(false); expect(detail.has("search")).toBe(false); expect(detail.has("collection")).toBe(false);
  expect(search.toString()).toBe(before);
});

it("pins relative time and retains unedited custom instants across an ambiguous DST hour", () => {
  const fixed = initialSearch("?period=7d", new Date("2026-11-25T11:18:29.789Z"));
  expect(exactWindow(fixed, "UTC")).toEqual({ from: "2026-11-18T11:18:29.789Z", to: "2026-11-25T11:18:29.789Z" });
  const fold = new URLSearchParams("period=custom&from=2026-11-01T06:10:20.123Z&to=2026-11-01T06:40:20.456Z");
  const displayed = filterValues(fold, "America/New_York");
  expect(displayed.period).toEqual({ preset: "custom", from: "2026-11-01T01:10:20.123", to: "2026-11-01T01:40:20.456" });
  expect(appliedFilters(displayed, fold, "America/New_York")).toMatchObject({ from: fold.get("from"), to: fold.get("to") });
  expect(exactWindow(new URLSearchParams("from=2026-11-25T10:00:00Z&to=2026-11-25T09:00:00Z"), "UTC")).toBeNull();
});

it("preserves saved-group counts and intervals without offering its representative ID as exact evidence", () => {
  const [group, event, unlinked] = eventRows([
    { id: 101, event_id: 4624, event_count: 39, journal_expandable: true, first_seen_utc: "2026-11-25T08:00:00Z", last_seen_utc: "2026-11-25T13:00:00Z", journal_evidence_available: true },
    { id: 102, event_id: 1102, event_count: 1, journal_evidence_available: true, journal_finding_id: 7, journal_severity: "high" },
    { id: 103, event_count: 1, journal_severity: "critical" },
  ]);
  expect(group).toMatchObject({ count: 39, first: "2026-11-25T08:00:00Z", last: "2026-11-25T13:00:00Z", group: true, evidenceAvailable: false });
  expect(evidenceHref(group, { domain_id: "11" } as Station, "/app/report/workstations.overview")).toBeNull();
  expect(event).toMatchObject({ evidenceAvailable: true, findingId: "7", severity: "high" });
  expect(unlinked.severity).toBeNull();
});

it("accepts nullable native metadata but rejects a retained inventory projection as a current station DTO", () => {
  const [station] = stationRows([{ station_id: source, agent_key: source, collection_state: "unbound", profile: { state: "unbound" }, last_seen: null }]);
  expect(station).toMatchObject({ last_seen: null, operating_system: null, journal_available: false, collection_state: "unbound" });
  expect(() => stationRows([{ station_id: "ws:ad:123", metadata: { display_name: "retained" } }])).toThrow("workstation_response_invalid");
});

it("keeps same-time workstation facts selectable when exact event IDs are withheld", () => {
  const time = "2026-11-25T10:00:00Z";
  const [process, device] = eventRows([
    { event_id: 4688, time_created_utc: time, event_count: 2, journal_expandable: true,
      workstation_event: { image_path: "C:\\Tools\\editor.exe" } },
    { event_id: 6416, time_created_utc: time, event_count: 1, workstation_event: { device_name: "Example USB drive" } },
  ]);
  expect(process).toMatchObject({ id: null, imagePath: "C:\\Tools\\editor.exe", group: true, evidenceAvailable: false });
  expect(device).toMatchObject({ id: null, deviceName: "Example USB drive", group: false, evidenceAvailable: false });
  expect(process.key).not.toBe(device.key);
});

it("restores a workstation-local fleet URL and carries the exact server-provided source into journal links", () => {
  const original = `/app/report/workstations.overview?${windowQuery}&search=WS-&cursor=station-page&source_instance_id=${source}`;
  const search = new URLSearchParams({ station: source, station_return: original });
  expect(fleetReturnHref(search, "/app/report/workstations.overview")).toBe(original);
  search.set("station_return", "https://example.invalid/steal");
  expect(fleetReturnHref(search, "/app/report/workstations.overview")).toBe("/app/report/workstations.overview");
  const params = { domain: 11, server: "WS-1", source_instance_id: source, source_plugin: "sli.workstations", period: "custom", from: "2026-11-25T09:14:23.456Z", to: "2026-11-25T11:18:29.789Z", tz: "UTC" };
  const detail: Pick<NonNullable<StationDetailResult["detail"]>, "related"> = { related: { journal: { allowed: true, params }, problems: { allowed: false } } };
  const link = new URL(journalHref(detail, original)!, "https://sli.example.invalid");
  for (const [key, value] of Object.entries(params)) expect(link.searchParams.get(key)).toBe(String(value));
  expect(link.searchParams.get("return_to")).toBe(original);
  expect(eventHistory(new URLSearchParams('event_history=[null,"bound-event-cursor"]'))).toEqual([null, "bound-event-cursor"]);
});
