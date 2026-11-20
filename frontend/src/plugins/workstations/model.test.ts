import { expect, it } from "vitest";
import { countText, lastInteractiveLogin, processDetails, stationRows, selection, requestParams, paging } from "./model";

it("keeps lower bounds and unknown distinct from exact zero", () => {
  expect(countText({ value: 3, relation: "at_least" }, "Unknown")).toBe("≥ 3");
  expect(countText({ value: null, relation: "unknown" }, "Unknown")).toBe("Unknown");
  expect(countText({ value: 0, relation: "exact" }, "Unknown")).toBe("0");
});

it("rejects a malformed DTO instead of rendering an empty fleet", () => {
  expect(() => stationRows([{ metadata: {} }])).toThrow("workstation_response_invalid");
});

it("preserves list/card/evidence return state but sends only declared API filters", () => {
  const search = new URLSearchParams("search=synthetic&domain=11&cursor=station-50&station=station-51&finding=" + "a".repeat(64) + "&evidence=0");
  expect(selection(search)).toEqual({ station: "station-51", finding: "a".repeat(64), evidence: 0 });
  const request = requestParams(search, "UTC");
  expect(request.get("domain")).toBe("11");
  expect(request.get("cursor")).toBe("station-50");
  expect(request.has("station")).toBe(false);
  expect(request.has("finding")).toBe(false);
  expect(request.get("limit")).toBe("50");
});

it("uses server-scoped position and previous cursor for five-row check pages", () => {
  expect(paging([{ start: 11, has_previous: true, previous_cursor: "station-5" }]))
    .toEqual({ start: 11, hasPrevious: true, previousCursor: "station-5" });
  expect(paging([{ start: 6, has_previous: true, previous_cursor: null }]))
    .toEqual({ start: 6, hasPrevious: true, previousCursor: null });
  expect(paging(undefined)).toEqual({ start: 1, hasPrevious: false, previousCursor: null });
});

it.each(["domain_id=11", "domain=22&domain_id=11", "domain_id=11&domain=22"])("normalizes shell domain alias and precedence (%s)", (scope) => {
  const search = new URLSearchParams(`${scope}&station=ws%3Aad%3A123&cursor=ws%3Aad%3A100`);
  const original = search.toString();
  const request = requestParams(search, "UTC");
  expect(request.get("domain")).toBe("11");
  expect(request.has("domain_id")).toBe(false);
  expect(request.get("cursor")).toBe("ws:ad:100");
  expect(selection(search).station).toBe("ws:ad:123");
  expect(search.toString()).toBe(original);
});


it("keeps SID separate from a missing native account name and rejects timezone-free dates", () => {
  const row = { observed_at: "2026-10-19T12:30:00Z", logon_type: 11, account: { sid: "S-1-5-21-1-2-3-1001" } };
  expect(lastInteractiveLogin(row)).toEqual({ at: row.observed_at, type: 11, name: null, sid: row.account.sid });
  expect(lastInteractiveLogin({ ...row, observed_at: "2026-10-19T12:30:00" })).toBeNull();
  expect(lastInteractiveLogin({ ...row, logon_type: true })).toBeNull();
});


it("process card ignores unproven status and bounds only whitelisted values", () => {
  expect(processDetails({ check_id: "C04", process_details: { path: "x".repeat(513), process_id: "4294967296",
    signature_status: "signed", current_state: "active", command_line: "private" } }))
    .toEqual({ path: null, pid: null, signature: "unknown" });
  expect(processDetails({ check_id: "C04", process_details: {} })).toEqual({ path: null, pid: null, signature: "unknown" });
  expect(processDetails({ check_id: "C05", process_details: { path: "foreign" } })).toBeNull();
});
