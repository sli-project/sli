// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { caseStatusLabel } from "./case-status";
import { localeRuntime, setLocale, t } from "../i18n";
import catalog from "../../../config/i18n/server.ru.json";
import { ru } from "../i18n/ru";
import { en } from "../i18n/en";

const statusCodes = Object.keys(catalog).filter(
  (code): code is Extract<keyof typeof catalog, `investigations.caseStatus.${string}`> => code.startsWith("investigations.caseStatus."),
);

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

describe("caseStatusLabel", () => {
  it("translates known case and problem statuses and keeps unknown ones", () => {
    expect(caseStatusLabel("IN_PROGRESS")).toBe("В работе");
    expect(caseStatusLabel("dismissed")).toBe("Исключено");
    expect(caseStatusLabel("custom")).toBe("custom");
    expect(caseStatusLabel(null)).toBe("—");
  });

  it("keeps the investigation status vocabulary identical in the catalog and both UI locales", () => {
    expect(statusCodes.length).toBeGreaterThan(0);
    for (const dictionary of [ru, en]) {
      expect(Object.keys(dictionary).filter((code) => code.startsWith("investigations.caseStatus.")).sort()).toEqual([...statusCodes].sort());
    }
  });

  it.each(["ru", "en"] as const)("resolves every catalog investigation status in %s after module import", (locale) => {
    setLocale(locale);
    for (const code of statusCodes) {
      const status = code.slice("investigations.caseStatus.".length);
      expect(caseStatusLabel(status.toUpperCase())).toBe(t(code));
      expect(caseStatusLabel(status, { code, params: {}, text: "other language" })).toBe(t(code));
    }
    expect(caseStatusLabel("future", { code: "future.status", params: {}, text: "future label" })).toBe("future label");
  });
});
