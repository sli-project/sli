// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { localeRuntime, setLocale } from "../i18n";
import { dayKey, formatDate, formatDateTime, formatRelative, localDateTimeToUtc, utcToLocalDateTimeInput } from "./date-time";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });

describe("formatDateTime", () => {
  it("uses the selected IANA time zone", () => {
    const value = "2026-07-16T00:00:00Z";
    expect(formatDateTime(value, "UTC")).toBe("16.07.2026, 00:00");
    expect(formatDateTime(value, "Asia/Novosibirsk")).toBe("16.07.2026, 07:00");
  });

  it("does not turn an absent value into a fake timestamp", () => {
    expect(formatDateTime(null, "UTC")).toBe("—");
  });

  it("converts a Novosibirsk wall-clock filter to an exact UTC instant", () => {
    expect(localDateTimeToUtc("2026-07-16T12:00", "Asia/Novosibirsk")).toBe("2026-07-16T05:00:00.000Z");
    expect(utcToLocalDateTimeInput("2026-07-16T05:00:00Z", "Asia/Novosibirsk")).toBe("2026-07-16T12:00");
  });

  it("rejects malformed local filter values", () => {
    expect(localDateTimeToUtc("not-a-date", "Asia/Novosibirsk")).toBeNull();
  });
});

describe("one format per interface language", () => {
  afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });
  const use = (locale: "ru" | "en") => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale); };
  const value = "2026-10-21T14:05:00Z";

  it("ru: dd.mm.yyyy, hh:mm", () => {
    use("ru");
    expect(formatDateTime(value, "UTC")).toBe("21.10.2026, 14:05");
    expect(formatDate(value, "UTC")).toBe("21.10.2026");
  });

  it("en: month name, never a numeric day/month pair", () => {
    use("en");
    expect(formatDateTime(value, "UTC")).toBe("Oct 21, 2026, 2:05 PM");
    expect(formatDate(value, "UTC")).toBe("Oct 21, 2026");
    expect(formatDateTime(value, "Asia/Novosibirsk")).toBe("Oct 21, 2026, 9:05 PM");
  });

  it("shows the empty-value dash for absent or invalid input", () => {
    use("en");
    for (const empty of [null, undefined, "", "not a date"]) expect(formatDateTime(empty, "UTC")).toBe("—");
    expect(formatRelative(null)).toBe("—");
  });

  it("formats relative time by locale", () => {
    const now = Date.parse("2026-10-24T14:05:00Z");
    use("en");
    expect(formatRelative(value, { now })).toBe("3 days ago");
    use("ru");
    expect(formatRelative(value, { now })).toBe("3 дня назад");
  });

  it("builds a stable calendar-day key in a zone", () => {
    expect(dayKey("2026-10-21T20:00:00Z", "Asia/Novosibirsk")).toBe("2026-10-22");
    expect(dayKey("bad", "UTC")).toBeNull();
  });
});

describe("calendar dates are not instants", () => {
  afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });
  it.each(["ru", "en"] as const)("keeps the calendar day in %s across western time zones", (locale) => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
    expect(formatDate("2026-01-01", "America/Los_Angeles")).toBe(locale === "ru" ? "01.01.2026" : "Jan 1, 2026");
    expect(formatDate("2026-02-30", "UTC")).toBe("—");
  });
});
