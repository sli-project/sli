import { describe, expect, it } from "vitest";
import { scheduleFilterParams, scheduleFilterValues } from "./report-schedule-filters";

const metadata = { key: "security.problems", params: [
  { key: "severity", kind: "choice" as const, label: "Severity", options: [{ value: "high", label: "High" }, { value: "critical", label: "Critical" }] },
  { key: "risk", kind: "choice" as const, label: "Risk", options: [{ value: "accepted", label: "Accepted" }] },
  { key: "q", kind: "text" as const, label: "Search" },
] };

describe("schedule filters from the report declaration", () => {
  it("uses exact declared labels/values and excludes unsupported or personal filters", () => {
    expect(scheduleFilterParams("security.problems", metadata)).toEqual([metadata.params[0]]);
  });
  it("serializes only declared single values, omitting the report-default selection", () => {
    const params = [metadata.params[0]];
    expect(scheduleFilterValues(params, { severity: "high" })).toEqual({ severity: "high" });
    expect(scheduleFilterValues(params, { severity: "" })).toEqual({});
  });
  it.each(["high,critical", ">=high", "unknown"])("rejects unsupported value %s", (severity) => {
    expect(scheduleFilterValues([metadata.params[0]], { severity })).toBeNull();
  });
  it("rejects stale selections instead of silently broadening the saved filter", () => {
    expect(scheduleFilterValues([], { severity: "high" })).toBeNull();
    expect(scheduleFilterValues([metadata.params[0]], { q: "private" })).toBeNull();
  });
  it("rejects absent, wrong-report and malformed metadata", () => {
    expect(scheduleFilterParams("security.problems", undefined)).toBeNull();
    expect(scheduleFilterParams("file-audit.mass-operations", metadata)).toBeNull();
    expect(scheduleFilterParams("security.problems", { ...metadata, params: [{ ...metadata.params[0], options: undefined }] })).toBeNull();
  });
  it("does not mutate declaration or selection", () => {
    const original = JSON.stringify(metadata);
    const selected = { severity: "high" };
    scheduleFilterParams("security.problems", metadata);
    scheduleFilterValues([metadata.params[0]], selected);
    expect(JSON.stringify(metadata)).toBe(original);
    expect(selected).toEqual({ severity: "high" });
  });
});
