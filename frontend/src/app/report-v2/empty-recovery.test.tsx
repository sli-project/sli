import { describe, expect, it } from "vitest";
import type { ReportResultDto } from "../../api/report-v2-types";
import { reportEmptyRecovery } from "./empty-recovery";

const result = (coverage: ReportResultDto["coverage"], window: ReportResultDto["window"] = {}): ReportResultDto => ({
  contract_id: "sli.report-result.v2", report_key: "demo.events", state: "empty", items: [], metrics: [], coverage, window,
  has_more: false, next_cursor: null, filtered_count: null, series: {}, filter_options: {}, limitations: [],
});

describe("reportEmptyRecovery", () => {
  it.each([["Asia/Bangkok", "2026-09-02"], ["America/Los_Angeles", "2026-09-01"], ["UTC", "2026-09-01"]])("includes the last instant in the selected day for %s", (zone, day) => {
    expect(reportEmptyRecovery(result({ history_to_utc: "2026-09-01T23:30:00Z" }), zone)?.period).toEqual({ preset: "custom", from: day, to: day });
  });

  it("does not mistake a generated window, a source domain ID or invalid metadata for available data", () => {
    expect(reportEmptyRecovery(result({}, { generated_at_utc: "2026-09-01T23:30:00Z", source_domain_id: 1 }), "UTC")).toBeNull();
    expect(reportEmptyRecovery(result({ history_to_utc: "invalid", observed_at_utc: 10 }), "UTC")).toBeNull();
    expect(reportEmptyRecovery(undefined, "UTC")).toBeNull();
  });

  it("withholds the jump when the timezone is unavailable, retaining server time and diagnostics", () => {
    const recovery = reportEmptyRecovery(result({ observed_at_utc: "2026-09-01T23:30:00Z" }, { from_utc: "2026-09-01T00:00:00Z", to_utc: "2026-09-02T00:00:00Z" }), "invalid:sample");
    expect(recovery?.period).toBeNull();
    expect(recovery?.lastAt).toBe("2026-09-01T23:30:00Z");
    expect(recovery?.sourceHref).toBe("/app/operations");
    expect(recovery?.originalPeriod).toContain("sample");
  });

  it("encodes the source hostname from the response", () => {
    expect(reportEmptyRecovery(result({ source: { hostname: "sample/source" } }), "UTC")?.sourceHref).toBe("/app/operations/sources/sample%2Fsource");
  });

  it("names the selected period when the server omits the resolved window", () => {
    const data = result({ history_to_utc: "2026-09-01T23:30:00Z" });
    expect(reportEmptyRecovery(data, "UTC", { preset: "7d" })?.originalPeriod).toBe("Исходный период: 7 дней");
    expect(reportEmptyRecovery(data, "UTC", { preset: "custom", from: "2026-09-10", to: "2026-09-11" })?.originalPeriod).toBe("Исходный период: с 2026-09-10 до 2026-09-11");
  });
});
