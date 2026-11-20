// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { formatCell, formatDateTime, setDisplayTimeZone } from "./format";
import { buildChartOption } from "./Chart";
import { localizeReportRow } from "../i18n/report-metadata";
import { localeRuntime, setLocale } from "../i18n";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
const stamp = "2026-10-08T23:05:00Z";
const explicitDate = formatDateTime as (value: string, withTime: boolean, zone: string) => string;
const explicitCell = formatCell as (value: unknown, kind: "datetime", zone: string) => string;
afterEach(() => { setDisplayTimeZone(undefined); setLocale("ru"); vi.restoreAllMocks(); });
it("uses the explicit zone instead of a different mutable fallback", () => {
  setDisplayTimeZone("UTC");
  expect(explicitDate(stamp, true, "Asia/Novosibirsk")).toBe("09.10.2026, 06:05");
  expect(explicitCell(stamp, "datetime", "Asia/Novosibirsk")).toBe("09.10.2026, 06:05");
});
it("captures the chart zone without moving calendar-day buckets", () => {
  const colors = { text: "", muted: "", grid: "", palette: [], accent: "", surface: "" };
  const build = buildChartOption as (spec: Parameters<typeof buildChartOption>[0], colors: Parameters<typeof buildChartOption>[1], zone: string) => ReturnType<typeof buildChartOption>;
  setDisplayTimeZone("UTC");
  const option = build({ kind: "timeseries", series: [{ name: "n", points: [{ x: stamp, y: 1 }] }] }, colors, "Asia/Novosibirsk");
  expect((option.xAxis as { axisLabel: { formatter: (value: number) => string } }).axisLabel.formatter(Date.parse(stamp))).toBe("09.10.2026, 06:05");
  const days = build({ kind: "timeseries", series: [{ name: "n", points: [{ x: "2026-10-08", y: 1 }] }] }, colors, "America/Los_Angeles");
  expect((days.xAxis as { data: string[] }).data).toEqual(["08.10"]);
});
it.each(["ru", "en"] as const)("localizes metadata in its query zone without altering source evidence (%s)", (locale) => {
  setLocale(locale); setDisplayTimeZone("UTC");
  const row = { control_id: "trust.direction", actual_value: stamp, actual_text: stamp, object_context: { last_replication_attempt_utc: stamp }, context: [{ code: "last_replication_attempt_utc", value: stamp }] };
  const localize = localizeReportRow as (report: string, row: Record<string, unknown>, zone: string) => Record<string, unknown>;
  const result = localize("ad.infrastructure", row, "Asia/Novosibirsk");
  expect(result.actual_text).toBe(locale === "ru" ? "09.10.2026, 06:05" : "Oct 9, 2026, 6:05 AM");
  expect(result.actual_value).toBe(stamp);
  expect(result.object_context).toBe(row.object_context);
  expect(row.actual_text).toBe(stamp);
});

import { cleanup, render, screen } from "@testing-library/react";
import { TimeZoneContext } from "../shared/time-zone";
import { DataTable } from "./DataTable";
afterEach(cleanup);
it("renders table dates in the provider zone immediately and after a zone change", () => {
  const columns = [{ key: "stamp", label: "Time", kind: "datetime" as const }];
  const rows = [{ stamp }];
  const table = <DataTable columns={columns} rows={rows} rowKey={(row) => row.stamp} caption="Times"/>;
  const view = (timeZone: string) => <TimeZoneContext.Provider value={{ timeZone, setTimeZone: () => undefined }}>{table}</TimeZoneContext.Provider>;
  setDisplayTimeZone("UTC");
  const { rerender } = render(view("Asia/Novosibirsk"));
  expect(screen.getAllByText("09.10.2026, 06:05").length).toBeGreaterThan(0);
  rerender(view("America/Los_Angeles"));
  expect(screen.getAllByText("08.10.2026, 16:05").length).toBeGreaterThan(0);
  expect(screen.queryByText("09.10.2026, 06:05")).toBeNull();
});
