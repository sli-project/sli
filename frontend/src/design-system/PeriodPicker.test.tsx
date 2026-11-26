// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { PeriodPicker, periodBounds, previousPeriod } from "./PeriodPicker";

afterEach(cleanup);
it("accepts whole days and preserves the exact local time selected", () => {
  const change = vi.fn();
  const { rerender } = render(<PeriodPicker value={{ preset: "custom" }} onChange={change}/>);
  expect(screen.getByLabelText("С").getAttribute("placeholder")).toBe("ГГГГ-ММ-ДД");
  rerender(<PeriodPicker value={{ preset: "custom", from: "2026-10-01T09:15", to: "2026-10-01T10:45" }} precision="datetime-local" onChange={change}/>);
  expect((screen.getByLabelText("С") as HTMLInputElement).value).toBe("2026-10-01 09:15");
  fireEvent.change(screen.getByLabelText("По"), { target: { value: "2026-10-01 11:30" } });
  expect(change).toHaveBeenCalledWith({ preset: "custom", from: "2026-10-01T09:15", to: "2026-10-01T11:30" });
});

it("resolves precise local bounds and retains whole-day bounds for existing reports", () => {
  expect(periodBounds({ preset: "custom", from: "2026-10-01T09:15", to: "2026-10-01T10:45" })).toEqual({
    from: new Date("2026-10-01T09:15").toISOString(), to: new Date("2026-10-01T10:45").toISOString(),
  });
  expect(periodBounds({ preset: "custom", from: "2026-10-01", to: "2026-10-01" })).toEqual({
    from: new Date("2026-10-01T00:00:00").toISOString(), to: new Date("2026-10-01T23:59:59.999").toISOString(),
  });
  expect(periodBounds({ preset: "custom", from: "2026-10-01T10:45", to: "2026-10-01T09:15" })).toBeNull();
});

it("selects the immediately preceding window, including repeated shifts and inclusive calendar dates", () => {
  const previous = previousPeriod({ preset: "24h" }, { from: "2026-11-21T08:00:00Z", to: "2026-11-22T08:00:00Z" });
  expect(previous).toEqual({ preset: "custom", from: "2026-11-20T08:00:00.000Z", to: "2026-11-21T08:00:00Z" });
  expect(previousPeriod(previous!)).toEqual({ preset: "custom", from: "2026-11-19T08:00:00.000Z", to: "2026-11-20T08:00:00.000Z" });
  expect(previousPeriod({ preset: "custom", from: "2026-11-01", to: "2026-11-03" })).toEqual({
    preset: "custom", from: "2026-10-29", to: "2026-10-31",
  });
});
