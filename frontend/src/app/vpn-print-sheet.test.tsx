// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

vi.mock("./App", () => ({ useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("./vpn-session-evidence", () => ({ VpnConnectionSessionEvidence: ({ sessionRowId }: { sessionRowId: string }) => <p>evidence {sessionRowId}</p> }));

import { VpnActivityStrip } from "./vpn-activity-strip";
import { confirmedTime, VpnPrintSheet } from "./vpn-print-sheet";
import { vpnDuration } from "./vpn-day-drawer";
import { localeRuntime, setLocale } from "../i18n";

afterEach(() => {
  cleanup();
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  vi.restoreAllMocks();
  localStorage.clear();
});

const rows = [
  { entity_id: 1, display_name: "Иванов", account_name: "ivanov", department: "ИТ", session_count: 2, closed_session_count: 2, open_session_count: 0, confirmed_minutes: 125, overlap_count: 0 },
  { entity_id: 2, display_name: "Петров", account_name: "petrov", department: "ИБ", session_count: 1, closed_session_count: 0, open_session_count: 1, confirmed_minutes: 0, overlap_count: 1 },
];

it("formats durations and never shows open-only time as zero", () => {
  expect(vpnDuration(7500)).toBe("2 ч 05 мин");
  expect(vpnDuration(null)).toBe("не вычисляется");
  expect(confirmedTime(rows[0])).toBe("2 ч 05 мин");
  expect(confirmedTime(rows[1])).toBe("не подтверждено");
});

it("prints only the chosen employees", () => {
  render(<VpnPrintSheet rows={rows} result={{ window: { local_from_date: "2026-09-01", local_to_date: "2026-09-30", timezone: "UTC" }, has_more: false } as never}/>);
  fireEvent.click(screen.getByRole("button", { name: "Печатный лист" }));
  expect((screen.getByRole("button", { name: /Печать ·/ }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByLabelText(/Петров/));
  const sheet = document.querySelector(".sli-ds-print-sheet")!;
  expect(sheet.textContent).toContain("Петров");
  expect(sheet.textContent).not.toContain("Иванов");
  expect(sheet.textContent).toContain("01.09.2026 — 30.09.2026");
  expect(sheet.textContent).toContain("Есть сессии без подтверждённого конца");
});

it("opens the day's sessions from the strip and the chosen session's evidence", () => {
  const row = { entity_id: 7, display_name: "Сидоров", sessions: [
    { session_row_id: "s1", started_at_utc: "2026-09-14T03:00:00Z", stopped_at_utc: "2026-09-14T04:00:00Z", lifecycle_state: "closed", duration_seconds: 3600 },
  ] };
  const onRow = vi.fn();
  render(<div onClick={onRow}><VpnActivityStrip row={row} window={{ local_from_date: "2026-09-13", local_to_date: "2026-09-15", timezone: "UTC", source_domain_id: 5 }}/></div>);
  fireEvent.click(screen.getByRole("button", { name: /14\.09: 1 сессия.*Открыть сессии дня/ }));
  expect(onRow).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: /1 ч 00 мин · Завершена/ }));
  expect(screen.getByText("evidence s1")).toBeTruthy();
  expect(onRow).not.toHaveBeenCalled();
});

it.each([1, 2, 5, 21])("translates session counts and print selection for %s employees", (count) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  const employees = Array.from({ length: count }, (_, index) => ({ entity_id: index, display_name: `Employee ${index}` }));
  render(<VpnActivityStrip row={{ sessions: Array.from({ length: count }, () => ({})) }}/>);
  expect(screen.getByText(`${count} ${count === 1 ? "session" : "sessions"}`)).toBeTruthy();
  render(<VpnPrintSheet rows={employees} result={{ has_more: true } as never}/>);
  fireEvent.click(screen.getByRole("button", { name: "Print sheet" }));
  expect(screen.getByText(`Choose from ${count} loaded ${count === 1 ? "employee" : "employees"}; more are available — load the table to select the rest.`)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Select all visible" }));
  expect(screen.getByRole("button", { name: `Print · ${count} ${count === 1 ? "employee" : "employees"}` })).toBeTruthy();
});

it("translates the session count in a day's accessible label", () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  render(<VpnActivityStrip row={{ sessions: [{ started_at_utc: "2026-09-14T03:00:00Z", stopped_at_utc: "2026-09-14T04:00:00Z", lifecycle_state: "closed" }] }}
    window={{ local_from_date: "2026-09-14", local_to_date: "2026-09-14", timezone: "UTC" }}/>);
  expect(screen.getByRole("button", { name: /1 session, sessions closed/ })).toBeTruthy();
});

 it("uses English calendar dates in the activity label and day drawer", () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("en");
  render(<VpnActivityStrip row={{ display_name: "Synthetic user", sessions: [{ session_row_id: "s1", started_at_utc: "2026-09-14T03:00:00Z", stopped_at_utc: "2026-09-14T04:00:00Z", lifecycle_state: "closed" }] }}
    window={{ local_from_date: "2026-09-14", local_to_date: "2026-09-14", timezone: "UTC" }}/>);
  fireEvent.click(screen.getByRole("button", { name: /Sep 14: 1 session/ }));
  expect(screen.getByRole("dialog").textContent).toContain("Sep 14, 2026");
});
