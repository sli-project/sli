import { describe, expect, it } from "vitest";
import { chainFilters } from "./security-chains-view";
import { securityEventsExactSelectorError, vpnAccountingIsolatedByWindowsFilters } from "./security-events-report";

describe("chain filters from the report parameters", () => {
  const window = { from_utc: "2026-09-11T10:20:30Z", to_utc_exclusive: "2026-09-11T11:20:30Z" };

  it("use the server-resolved window and every applied filter", () => {
    const filters = chainFilters(new URLSearchParams("domain=7&period=custom&tz=Asia%2FBangkok&category=group_membership&event_id=4728&actor=operator&entity_id=12"), window, "UTC");
    expect(filters).toMatchObject({ domainId: 7, timeFrom: window.from_utc, timeTo: window.to_utc_exclusive, timeZone: "Asia/Bangkok", category: "group_membership", eventId: "4728", actor: "operator", entityId: "12", limit: 200 });
    expect(vpnAccountingIsolatedByWindowsFilters(filters!)).toBe(true);
  });

  it("make no request without a domain or a resolved window", () => {
    expect(chainFilters(new URLSearchParams("period=7d"), window, "UTC")).toBeNull();
    expect(chainFilters(new URLSearchParams("domain=7"), undefined, "UTC")).toBeNull();
  });

  it("keep an invalid exact selector visible instead of widening the query", () => {
    const filters = chainFilters(new URLSearchParams("domain=7&entity_id=abc"), window, "UTC");
    expect(securityEventsExactSelectorError(filters!)).toContain("ID объекта в SLI");
  });
});
