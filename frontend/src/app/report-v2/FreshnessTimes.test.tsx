// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { localeRuntime, setLocale, t } from "../../i18n";
import { FreshnessTimes, freshnessSummary } from "./FreshnessTimes";

afterEach(() => { cleanup(); vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); });

it("omits missing and invalid clocks while labeling valid dates separately", () => {
  const { container } = render(<FreshnessTimes event="invalid" snapshot={null} published="2026-10-07T00:00:00Z" observed={42} timeZone="UTC"/>);
  expect(container.querySelectorAll("span")).toHaveLength(1);
  expect(container.textContent).toBe(t("reports.freshness.published", { time: "07.10.2026, 00:00" }));
  expect(container.textContent).not.toContain(t("reports.passport.unknown"));
});

it.each(["ru", "en"] as const)("dates source data before publication and formats its age (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-08T00:00:00Z"));
  const summary = freshnessSummary({ event: "2026-09-15T00:00:00Z", published: "2026-10-07T00:00:00Z", timeZone: "UTC" });
  expect(summary).toBe(t("reports.freshness.data_date", { time: locale === "ru" ? "15.09.2026" : "Sep 15, 2026", age: locale === "ru" ? "23 дня назад" : "23 days ago" }));
  expect(freshnessSummary({ published: "2026-10-07T00:00:00Z", timeZone: "UTC" })).toBe(t("reports.freshness.publication_date", {
    time: locale === "ru" ? "07.10.2026" : "Oct 7, 2026", age: locale === "ru" ? "вчера" : "yesterday",
  }));
});

it("uses observation then snapshot then event, without inventing an unknown date", () => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-08T00:00:00Z"));
  expect(freshnessSummary({ observed: "2026-09-15T00:00:00Z", snapshot: "2026-09-16T00:00:00Z", event: "2026-09-17T00:00:00Z", timeZone: "UTC" })).toContain("23");
  expect(freshnessSummary({ observed: "invalid", snapshot: "2026-09-16T00:00:00Z", timeZone: "UTC" })).toContain("22");
  expect(freshnessSummary({ observed: "2026-09-15T23:00:00Z", timeZone: "Asia/Bangkok" })).toContain("16.09.2026");
  expect(freshnessSummary({})).toBeNull();
});

it("does not label a slightly future timestamp as a whole day ahead", () => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-08T00:00:00Z"));
  expect(freshnessSummary({ observed: "2026-10-08T01:00:00Z", timeZone: "UTC" })).toContain("сегодня");
});
