// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { PeriodPicker, periodBounds } from "./PeriodPicker";

afterEach(cleanup);
it("keeps date inputs by default and supports exact date-time inputs when requested", () => {
  const change = vi.fn();
  const { rerender } = render(<PeriodPicker value={{ preset: "custom" }} onChange={change}/>);
  expect((screen.getByLabelText("С") as HTMLInputElement).type).toBe("date");
  rerender(<PeriodPicker value={{ preset: "custom", from: "2026-10-01T09:15", to: "2026-10-01T10:45" }} precision="datetime-local" onChange={change}/>);
  expect((screen.getByLabelText("С") as HTMLInputElement).type).toBe("datetime-local");
  fireEvent.change(screen.getByLabelText("По"), { target: { value: "2026-10-01T11:30" } });
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
