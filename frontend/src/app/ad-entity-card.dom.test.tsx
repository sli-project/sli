// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { api, type EntityWorkspaceDetail } from "../api/client";
import type { ReportResultDto } from "../api/report-v2-types";
import { buildChartOption } from "../design-system/Chart";
import { t } from "../i18n";
import { TimeZoneContext } from "../shared/time-zone";
import { AdEntityCard } from "./ad-entity-card";

const from = "2026-11-20T00:00:00Z";
const to = "2026-11-28T00:00:00Z";
const zone = "Asia/Bangkok";
const eventTime = "2026-11-27T20:26:00Z";
const report = (items: Record<string, unknown>[], patch: Partial<ReportResultDto> = {}) => ({
  items, state: "ok", coverage: {}, ...patch,
} as ReportResultDto);
const workspace = (type: string) => ({
  entity: { id: 7, type, domain_id: 1, natural_key: "", display_name: "Example object" },
  context: { time_from_utc: from, time_to_utc_exclusive: to, timezone: zone },
} as EntityWorkspaceDetail);

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function mount(type: string, tab = "") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const selectTab = vi.fn();
  const renderCard = (requestedTab: string) => <QueryClientProvider client={client}>
    <TimeZoneContext.Provider value={{ timeZone: zone, setTimeZone: () => undefined }}>
      <AdEntityCard data={workspace(type)} fields={new Map()} requestedTab={requestedTab} selectTab={selectTab}
        location="/app/entities/7" returnTo="/app/objects" timeZone={zone}/>
    </TimeZoneContext.Provider>
  </QueryClientProvider>;
  const view = render(renderCard(tab));
  return { selectTab, open: (value: string) => view.rerender(renderCard(value)) };
}

it("scopes the counts by object and opens the failed checks that were counted", async () => {
  const data = vi.spyOn(api, "reportV2Data").mockImplementation(async (key, params) => {
    if (key === "security.problems") return report(
      [{ id: 12, title_text: "Example open problem", severity: "medium", last_seen_utc: eventTime }],
      { coverage: { open_by_severity: { medium: 1 } } },
    );
    if (key === "security.events.chains") return report([], { filtered_count: 3 });
    if (params.get("tab") === "checks") return report([
      { key: "delegation", title: "Example failed check", severity: "high", last_seen_utc: eventTime },
    ]);
    return report([{ entity_id: 7, computer_type: "workstation" }]);
  });
  const view = mount("ad_computer");
  expect(screen.getByRole("tab", { name: t("entities.card.important") }).getAttribute("aria-selected")).toBe("true");
  const rows = within(await screen.findByRole("table", { name: t("entities.card.important") })).getAllByRole("row");
  expect(rows[1].textContent).toContain("Example failed check");
  expect(rows[2].textContent).toContain("Example open problem");
  const problemsLink = await screen.findByRole("link", { name: /1 →/ });
  const problemsParams = new URL(problemsLink.getAttribute("href")!, "http://localhost").searchParams;
  expect(problemsParams.get("entity_id")).toBe("7");
  expect(problemsParams.get("population")).toBe("open");
  const changesLink = await screen.findByRole("link", { name: /3 →/ });
  const changesParams = new URL(changesLink.getAttribute("href")!, "http://localhost").searchParams;
  for (const key of ["domain", "entity_id", "from", "to", "repeat_mode"])
    expect(changesParams.get(key)).toBe(data.mock.calls.find(([key]) => key === "security.events.chains")?.[1].get(key));
  const count = screen.getByRole("button", { name: t("entities.card.failedChecksCount", { count: "1" }) });
  fireEvent.click(count);
  expect(view.selectTab).toHaveBeenCalledWith("checks");
  view.open("checks");
  expect(screen.queryByText("Example open problem")).toBeNull();
  expect(screen.getByText("Example failed check")).toBeTruthy();
  expect(data.mock.calls.find(([, params]) => params.get("tab") === "checks")?.[1].get("entity_id")).toBe("7");
});

it("shows one latest activity with its source and formats repetitions in the app time zone", async () => {
  vi.spyOn(api, "reportV2Data").mockResolvedValue(report([]));
  const detail = vi.spyOn(api, "reportV2Detail").mockResolvedValue(report([{
    activity_at: eventTime, activity_source: "windows_event",
    timeline: [{ id: 12, event_id: 4624, at_utc: eventTime, first_seen_utc: "2026-11-27T18:00:00Z", event_count: 2 }],
  }]));
  const view = mount("ad_user", "properties");
  const activity = await screen.findByText(new RegExp(t("reports.ad.users.card.source_event")));
  expect(activity.textContent).toContain("03:26:00");
  expect(detail.mock.calls[0][2].get("tz")).toBe(zone);
  view.open("activity");
  const collapse = screen.getByRole("checkbox", { name: t("reports.ad.users.card.collapse") });
  expect(collapse.closest(".sli-ds-check")).toBeTruthy();
  expect(screen.getByRole("link", { name: /03:26/ })).toBeTruthy();
  expect(screen.queryByText(/обычно в день|typical per day/i)).toBeNull();
});

it("shows an integer per-day axis and a line legend for successful logons", () => {
  const unit = t("reports.ad.users.card.logons_per_day");
  const chart = buildChartOption({ kind: "timeseries", unit, series: [
    { style: "bar", name: "Failures", points: [{ x: "2026-11-28", y: 1 }] },
    { style: "line", name: "Successes", points: [{ x: "2026-11-28", y: 2 }] },
  ] }, { text: "#000", muted: "#555", grid: "#ccc", palette: [], accent: "#00f", surface: "#fff" });
  expect(chart.yAxis).toMatchObject({ name: unit, minInterval: 1 });
  expect(chart.legend).toMatchObject({ data: [
    { name: "Failures", icon: "roundRect" },
    { name: "Successes", icon: expect.stringMatching(/^path:\/\//) },
  ] });
});
