import { expect, it } from "vitest";
import { uniqueApprovalInstant } from "./approval-time";

it.each([
  ["2026-03-08T02:30", "America/New_York", null],
  ["2026-11-01T01:30", "America/New_York", null],
  ["2026-12-01T06:00", "America/New_York", "2026-12-01T11:00:00.000Z"],
  ["2026-12-01T18:00", "Asia/Novosibirsk", "2026-12-01T11:00:00.000Z"],
  ["2026-12-01T17:45", "Asia/Kathmandu", "2026-12-01T12:00:00.000Z"],
  ["2026-03-08T02:30", "UTC", "2026-03-08T02:30:00.000Z"],
  ["2026-11-01T01:30", "UTC", "2026-11-01T01:30:00.000Z"],
  ["2026-02-30T12:00", "UTC", null],
  ["2026-12-01T25:00", "UTC", null],
  ["2026-12-01T12:00", "invalid:zone", null],
  ["", "UTC", null],
  ["10000-12-01T12:00", "UTC", null],
  ["2026-12-01T12:00Z", "UTC", null],
])("resolves only a unique valid minute (%s, %s)", (value, zone, expected) => {
  expect(uniqueApprovalInstant(value, zone)).toBe(expected);
});
