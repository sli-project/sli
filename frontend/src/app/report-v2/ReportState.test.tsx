// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ReportState } from "./ReportState";
import { TimeZoneContext } from "../../shared/time-zone";
import { localeRuntime, setLocale, t } from "../../i18n";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

describe.each(["ru", "en"] as const)("report states in %s", (locale) => {
  it.each(["partial", "stale", "processing", "not_collected"] as const)("keeps %s silent without a source name and valid time", (state) => {
    setLocale(locale);
    const { container, rerender } = render(<ReportState state={state}/>);
    expect(container.innerHTML).toBe("");
    rerender(<ReportState state={state} details={{ reason: "source_failed", source: "fixture-source" }}/>);
    expect(container.innerHTML).toBe("");
    rerender(<ReportState state={state} details={{ reason: "freshness_exceeded", stale_since_utc: "2026-10-02T00:00:00Z" }}/>);
    expect(container.innerHTML).toBe("");
    rerender(<ReportState state={state} details={{ reason: "source_failed", source_issues: [{ source: "fixture-source", reason: "source_failed", since_utc: "invalid" }] }}/>);
    expect(container.innerHTML).toBe("");
  });

  it.each(["partial", "stale", "processing", "not_collected"] as const)("shows %s as one named and dated line without a banner", (state) => {
    setLocale(locale);
    const { container } = render(<TimeZoneContext.Provider value={{ timeZone: "UTC", setTimeZone: () => undefined }}>
      <ReportState state={state} details={{ reason: "source_failed", source_issues: [
        { source: "7:domain_health", source_name: "fixture-source", reason: "source_failed", since_utc: "2026-10-01T00:00:00Z" },
        { source: "other-source", reason: "source_missing", since_utc: "2026-10-02T00:00:00Z" },
      ] }}/>
    </TimeZoneContext.Provider>);
    expect(screen.getByRole("status").textContent).toBe(t("reports.states.silent_source", {
      source: "fixture-source", time: locale === "ru" ? "01.10.2026, 00:00" : "Oct 1, 2026, 12:00 AM",
    }));
    expect(container.querySelector(".sli-ds-state")).toBeNull();
    expect(container.querySelector("details")).toBeNull();
    expect(container.textContent).not.toContain("other-source");
  });
});

it.each(["fixture-source", { hostname: "fixture-source" }])("uses the named source and known freshness start", (source) => {
  render(<ReportState state="stale" details={{ reason: "freshness_exceeded", source, stale_since_utc: "2026-10-02T00:00:00Z" }}/>);
  expect(screen.getByRole("status").textContent).toContain("fixture-source");
  expect(screen.getByRole("status").textContent).toContain("2026");
});

it("does not reuse a freshness threshold as a failure start", () => {
  const { container } = render(<ReportState state="partial" details={{ reason: "source_failed", source: "fixture-source", stale_since_utc: "2026-10-02T00:00:00Z" }}/>);
  expect(container.innerHTML).toBe("");
});

it("retries errors and keeps ok silent", () => {
  const retry = vi.fn();
  const { rerender, container } = render(<ReportState state="error" subject="Fixture table" message={{ code: "reports.states.error.summary", params: {} }} onRetry={retry}/>);
  const alert = screen.getByRole("alert");
  expect(alert.textContent).toContain(t("reports.states.load_failed", { subject: "Fixture table" }));
  expect(alert.hasAttribute("data-tone")).toBe(false);
  expect(alert.classList.contains("sli-ds-state--banner")).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  expect(retry).toHaveBeenCalledTimes(1);
  rerender(<ReportState state="ok"/>);
  expect(container.innerHTML).toBe("");
});
