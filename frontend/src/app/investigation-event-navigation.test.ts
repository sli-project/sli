import { describe, expect, it } from "vitest";
import { exactEventInvestigationSearch } from "./event-card";

describe("exact event investigation navigation", () => {
  it("does not invent an empty time range when the user supplied none", () => {
    expect(exactEventInvestigationSearch(
      { event_db_id: 41, time_created_utc: "2026-09-10T12:00:00Z" }, "alice", "UTC", "",
    )).toEqual({ event_db_id: 41, q: "alice", scope: "important", timezone: "UTC" });
  });

  it("keeps the strict event ID admission before routing", () => {
    expect(() => exactEventInvestigationSearch(
      { event_db_id: 0, time_created_utc: "2026-09-10T12:00:00Z" }, "alice", "UTC", "",
    )).toThrow("invalid_event_db_id");
  });

  it("keeps the validated report return address when opening investigation context", () => {
    const report = "/app/security-events-report?category=account_lock&time_from=2026-09-10T12%3A00%3A00.123456Z";

    expect(exactEventInvestigationSearch(
      { event_db_id: 41, time_created_utc: "2026-09-10T12:00:00Z" },
      "alice",
      "UTC",
      `?event_db_id=41&return_to=${encodeURIComponent(report)}`,
    )).toEqual({
      event_db_id: 41,
      q: "alice",
      scope: "important",
      timezone: "UTC",
      return_to: report,
    });
  });
});
