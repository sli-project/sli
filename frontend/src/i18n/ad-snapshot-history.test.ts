// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale } from ".";
import { localizeReportView, reportMetadataText } from "./report-metadata";
import { ru } from "./ru";
import { en } from "./en";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => {}); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("localizes both history views, change kinds and partial coverage", () => {
  setLocale("en");
  for (const report of ["ad.infrastructure", "ad.gpo.v2"]) {
    const view = localizeReportView({ kind: "table", key: "changes", source: "changes", title: "Изменения",
      columns: [{ key: "kind", kind: "state", path: "kind", label: "Изменение",
        labels: { object_removed: "Объект удалён" } }] }, report);
    expect(view.title).toMatch(/changes/i);
    expect(view.columns?.[0].labels?.object_removed).toBe("Object removed");
    expect(reportMetadataText(report, "limitations.history_partial", "fallback")).toContain("does not fully cover");
  }
});

it("keeps history dictionary keys identical in both languages", () => {
  const keys = (messages: Record<string, string>) => Object.keys(messages).filter((key) =>
    key.startsWith("platformSettings.ad_history.") || key.includes(".history_partial") ||
    key.includes(".history_unavailable") || (key.includes(".views.changes.") &&
      (key.startsWith("reports.v2.ad.infrastructure.") || key.startsWith("reports.v2.ad.gpo.v2.")))).sort();
  expect(keys(en)).toEqual(keys(ru));
});
