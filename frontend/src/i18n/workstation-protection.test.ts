// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { en } from "./en";
import { ru } from "./ru";
import { localeRuntime, setLocale } from "./index";
import { localizeReportDefinition, reportMetadataText } from "./report-metadata";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("keeps protection translations aligned and explains snapshot freshness", () => {
  const prefix = "reports.v2.workstations.protection.";
  expect(Object.keys(en).filter((key) => key.startsWith(prefix)).sort())
    .toEqual(Object.keys(ru).filter((key) => key.startsWith(prefix)).sort());
  setLocale("en");
  expect(reportMetadataText("workstations.protection", "description", "fallback"))
    .toContain("snapshot time shows its freshness");
  const view = localizeReportDefinition({ key: "workstations.protection", section: "workstations",
    title: "Защита", description: "", archetype: "journal", params: [], views: [],
    row_key: "id", detail: "fields", export: false, limits: { default: 50, max: 500 },
    presets: [], row_links: [], filter_options: {}, columns: [
    { key: "protection_state", label: "Снимок защиты", kind: "state", path: "quality.state",
      labels: { available: "Получен", unavailable: "Недоступен" } },
    { key: "real_time_protection_enabled", label: "Защита в реальном времени", kind: "boolean",
      path: "facts.real_time_protection_enabled" },
  ] });
  expect(view.columns?.[0].label).toBe("Protection snapshot");
  expect(view.columns?.[0].labels?.unavailable).toBe("Unavailable");
  expect(view.columns?.[1].label).toBe("Real-time protection");
  expect(view.columns?.[1].path).toBe("facts.real_time_protection_enabled");
});
