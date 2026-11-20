import { describe, expect, it } from "vitest";
import type { V4Access } from "../api/client";
import { hasAllowedReport } from "./report-access";

describe("hasAllowedReport", () => {
  it("accepts production and prototype report-key aliases only when the server allows them", () => {
    const access = { reports: [
      { report_key: "events.explorer", allowed: true },
      { report_key: "investigations.workspace", allowed: false },
    ] } as V4Access;
    expect(hasAllowedReport(access, ["event.evidence", "events.explorer"])).toBe(true);
    expect(hasAllowedReport(access, ["cases.workspace", "investigations.workspace"])).toBe(false);
  });
});
