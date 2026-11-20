import { describe, expect, it } from "vitest";
import { entityWorkspaceApiParameters, investigationApiParameters, investigationContext, investigationDisplayTimeZone, investigationDisplayTimeZoneFromSearch, investigationParameters, investigationQueryKey, investigationRouterSearch, investigationSearch, investigationWorkspaceRequested, navigationHrefWithReturnTo, safeInvestigationReturnTo } from "./investigation-context";

describe("investigation navigation context", () => {
  it("admits only known local SLI pages as return destinations", () => {
    const exactReport = "/app/security-events-report?time_from=2026-09-10T12%3A00%3A00.123001Z#events";
    expect(safeInvestigationReturnTo(exactReport, "/app/entities")).toBe(exactReport);
    expect(safeInvestigationReturnTo("/app/events/517548?timezone=UTC", "/app/events")).toBe("/app/events/517548?timezone=UTC");
    expect(safeInvestigationReturnTo("https://outside.invalid/app/events", "/app/events")).toBe("/app/events");
    expect(safeInvestigationReturnTo("//outside.invalid/app/events", "/app/events")).toBe("/app/events");
    expect(safeInvestigationReturnTo("/app/admin", "/app/events")).toBe("/app/events");
    expect(safeInvestigationReturnTo("/app/events\\outside.invalid", "/app/events")).toBe("/app/events");
  });

  it("nests a validated return path without losing either query string", () => {
    expect(navigationHrefWithReturnTo(
      "/app/entities/42?time_from=2026-09-10T12%3A00%3A00.123001Z",
      "/app/events/517548?return_to=%2Fapp%2Fsecurity-events-report%3Fcategory%3Daccount_lock",
    )).toBe(
      "/app/entities/42?time_from=2026-09-10T12%3A00%3A00.123001Z&return_to=%2Fapp%2Fevents%2F517548%3Freturn_to%3D%252Fapp%252Fsecurity-events-report%253Fcategory%253Daccount_lock",
    );
  });

  it("transports exact entity history to the API and cache without name matching", () => {
    const context = investigationContext(new URLSearchParams("entity_id=42&time_from=2026-09-10&timezone=UTC"));
    expect(investigationApiParameters(context).get("entity_id")).toBe("42");
    expect(investigationQueryKey(context)[1]).toContain("entity_id=42");
  });
  it("opens the workspace for an exact entity even without optional filters", () => {
    expect(investigationWorkspaceRequested(investigationContext(new URLSearchParams("entity_id=42")))).toBe(true);
    expect(investigationWorkspaceRequested(investigationContext(new URLSearchParams()))).toBe(false);
  });
  it("retains exact evidence, selection, time and timezone without permission hints", () => {
    const context = investigationContext(new URLSearchParams("event_db_id=12&entity_id=9&scope=all&time_from=2026-09-10&time_to=2026-09-11&timezone=Asia%2FBangkok&admin=true"));
    expect(investigationParameters(context).toString()).toBe("event_db_id=12&entity_id=9&scope=all&time_from=2026-09-10&time_to=2026-09-11&timezone=Asia%2FBangkok");
  });
  it("updates the exact anchor without dropping the investigation period", () => {
    expect(investigationSearch("?event_db_id=12&time_from=2026-09-10&timezone=UTC", { event_db_id: "18" })).toEqual({ event_db_id: "18", time_from: "2026-09-10", timezone: "UTC" });
  });
  it("does not allow malformed identities to turn into a different query", () => {
    for (const value of ["0", "-1", "1.2", "1e2", "NaN", "9007199254740992"]) {
      expect(() => investigationContext(new URLSearchParams({event_db_id: value}))).toThrow("invalid_event_db_id");
    }
  });
  it("rejects a supplied empty exact identity but still permits an absent selection", () => {
    expect(investigationContext(new URLSearchParams("q=alice"))).toEqual({ q: "alice" });
    for (const search of ["event_db_id=", "event_db_id=%20%20", "entity_id=", "entity_id=%20"]) {
      expect(() => investigationContext(new URLSearchParams(search))).toThrow(/invalid_(event_db_id|entity_id)/);
    }
  });
  it("does not transport arbitrary external return destinations or grants", () => {
    expect(investigationSearch("?return_to=https://outside.invalid&capability=admin&q=alice", {})).toEqual({q:"alice"});
  });
  it("uses the same exact bounded context for the API request and query cache", () => {
    const context = investigationContext(new URLSearchParams("q=alice&event_db_id=12&scope=all&time_from=2026-09-10T00%3A00&time_to=2026-09-11T00%3A00&timezone=Asia%2FBangkok"));
    expect(investigationApiParameters(context).toString()).toBe("event_db_id=12&q=alice&scope=all&time_from=2026-09-10T00%3A00&time_to=2026-09-11T00%3A00&timezone=Asia%2FBangkok");
    expect(investigationQueryKey(context)).toEqual(["investigation", "event_db_id=12&q=alice&scope=all&time_from=2026-09-10T00%3A00&time_to=2026-09-11T00%3A00&timezone=Asia%2FBangkok"]);
  });
  it("adapts only admitted exact IDs to TanStack Router numeric search values", () => {
    expect(investigationRouterSearch(investigationContext(new URLSearchParams("event_db_id=12&entity_id=9&q=alice&scope=all&time_from=2026-09-10&timezone=UTC")))).toEqual({
      event_db_id: 12, entity_id: 9, q: "alice", scope: "all", time_from: "2026-09-10", timezone: "UTC",
    });
  });
  it("does not turn unchecked router IDs into a numeric search", () => {
    expect(() => investigationRouterSearch({ event_db_id: "\"12\"" })).toThrow("invalid_event_db_id");
    expect(() => investigationRouterSearch({ entity_id: "9007199254740992" })).toThrow("invalid_entity_id");
  });
  it("rejects malformed or inverted time context before a broad workspace request", () => {
    for (const search of ["q=alice&time_from=not-a-time", "q=alice&time_from=2026-02-30", "q=alice&time_from=2026-09-10T12%3A00%3A00.1234567Z", "q=alice&time_from=2026-09-11&time_to=2026-09-10", "q=alice&time_from=2026-09-10&time_from=2026-09-11"]) {
      expect(() => investigationContext(new URLSearchParams(search))).toThrow();
    }
  });
  it("keeps mixed date, local and explicit UTC bounds for server normalization", () => {
    expect(investigationContext(new URLSearchParams("event_db_id=12&time_from=2026-09-10T12%3A00%3A00Z&time_to=2026-09-10&timezone=UTC"))).toMatchObject({
      time_from: "2026-09-10T12:00:00Z", time_to: "2026-09-10", timezone: "UTC",
    });
    expect(investigationContext(new URLSearchParams("event_db_id=12&time_from=2026-09-10T12%3A00&time_to=2026-09-10T06%3A00%3A00Z&timezone=Asia%2FBangkok"))).toMatchObject({
      time_from: "2026-09-10T12:00", time_to: "2026-09-10T06:00:00Z", timezone: "Asia/Bangkok",
    });
  });
  it("still rejects only provably reversed homogeneous bounds and keeps a same-day date interval", () => {
    expect(investigationContext(new URLSearchParams("time_from=2026-09-10&time_to=2026-09-10"))).toMatchObject({ time_from: "2026-09-10", time_to: "2026-09-10" });
    expect(() => investigationContext(new URLSearchParams("time_from=2026-09-11&time_to=2026-09-10"))).toThrow("invalid_time_range");
    expect(() => investigationContext(new URLSearchParams("time_from=2026-09-10T12%3A00Z&time_to=2026-09-10T06%3A00Z"))).toThrow("invalid_time_range");
  });
  it("accepts backend microsecond UTC bounds without losing their ordering", () => {
    expect(investigationContext(new URLSearchParams("event_db_id=12&time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=UTC"))).toMatchObject({
      time_from: "2026-09-10T12:00:00.123001Z", time_to: "2026-09-10T12:00:00.123999Z", timezone: "UTC",
    });
    expect(() => investigationContext(new URLSearchParams("time_from=2026-09-10T12%3A00%3A00.123999Z&time_to=2026-09-10T12%3A00%3A00.123001Z"))).toThrow("invalid_time_range");
  });
  it("leaves timezone authority with the server while preserving its exact value", () => {
    const context = investigationContext(new URLSearchParams("event_db_id=12&timezone=Unknown%2FZone"));
    expect(investigationApiParameters(context).get("timezone")).toBe("Unknown/Zone");
  });
  it("does not reinterpret an explicit browser timezone as a global display preference", () => {
    const explicit = investigationContext(new URLSearchParams("event_db_id=12&timezone=browser"));
    expect(investigationDisplayTimeZone(explicit, "Asia/Novosibirsk")).toEqual({ timeZone: "invalid:browser", available: false });
    expect(investigationDisplayTimeZone(undefined, "browser")).toEqual({ timeZone: "browser", available: true });
  });
  it("keeps duplicate timezone input unavailable instead of silently falling back", () => {
    expect(investigationDisplayTimeZoneFromSearch("event_db_id=12&timezone=UTC&timezone=Asia%2FNovosibirsk", "browser"))
      .toEqual({ timeZone: "invalid:UTC, Asia/Novosibirsk", available: false });
    expect(investigationDisplayTimeZoneFromSearch("event_db_id=0", "browser"))
      .toEqual({ timeZone: "invalid:параметры контекста", available: false });
  });

  it("preserves exact fractional bounds for an entity workspace request", () => {
    const params = entityWorkspaceApiParameters("?time_from=2026-09-10T12%3A00%3A00.123456Z&time_to=2026-09-11T12%3A00%3A00.654321Z&timezone=Asia%2FBangkok", 50);
    expect(params.toString()).toBe("limit=50&time_from=2026-09-10T12%3A00%3A00.123456Z&time_to=2026-09-11T12%3A00%3A00.654321Z&timezone=Asia%2FBangkok");
  });

  it("rejects a partial entity time range instead of broadening the request", () => {
    expect(() => entityWorkspaceApiParameters("?time_from=2026-09-10T00%3A00%3A00Z", 50)).toThrow("entity_time_context_requires_both_bounds");
  });
});
