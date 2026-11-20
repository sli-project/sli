import { describe, expect, it } from "vitest";
import { normalizeCalendarBound } from "./event-filters";




describe("calendar day bounds", () => {
  it("starts a newly selected first day at midnight", () => {
    expect(normalizeCalendarBound("", "2026-07-01T13:54", "start")).toBe("2026-07-01T00:00");
  });

  it("ends a newly selected last day at the end of that day", () => {
    expect(normalizeCalendarBound("2026-07-01T00:00", "2026-07-03T13:54", "end")).toBe("2026-07-03T23:59:59");
  });

  it("preserves a deliberate time edit on the same date", () => {
    expect(normalizeCalendarBound("2026-07-03T23:59:59", "2026-07-03T18:30", "end")).toBe("2026-07-03T18:30");
  });
});
