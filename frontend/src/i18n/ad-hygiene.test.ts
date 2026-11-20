// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { ReportResultDto } from "../api/report-v2-types";
import { localeRuntime, setLocale } from "./index";
import { localizeReportResult, reportMetadataText } from "./report-metadata";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it.each([undefined, {}])("localizes reports without hygiene coverage (%s)", (coverage) => {
  setLocale("en");
  const items = [{ name: "Synthetic object", description: "Synthetic description" }];
  const collections = { objects: items };
  const result = {
    report_key: "ad.computers.v6", items, collections, metrics: [{ key: "all", label: "Всего в AD", value: 1 }],
    limitations: [], filter_options: {}, ...(coverage === undefined ? {} : { coverage }),
  } as unknown as ReportResultDto;

  const localized = localizeReportResult(result);
  expect(localized.metrics[0].label).toBe("Total in AD");
  expect(localized.items).toBe(items);
  expect(localized.collections).toBe(collections);
  expect(localized.coverage).toBe(coverage);
  expect(result.metrics[0].label).toBe("Всего в AD");
});

it("localizes policy results and unknown reasons while preserving facts and thresholds", () => {
  setLocale("en");
  const policy = { status: "unknown", reason: "fact_missing_or_invalid", threshold_days: 120, value: null, observed_at: "2026-10-01T00:00:00Z" };
  const exceeded = { ...policy, status: "exceeded", reason: null, value: "2026-01-01T00:00:00Z" };
  const reason = { key: "password_age_unknown", policy, label: "Возраст пароля: неизвестно", qualification: "Неизвестно",
    summary: "Неизвестно", observed: "pwdLastSet", condition: "Условие", limitation: "Ограничение", next: "Проверить" };
  const result: ReportResultDto = {
    contract_id: "sli.report-result.v2", report_key: "ad.users.v2", state: "partial", has_more: false, next_cursor: null,
    filtered_count: 1, metrics: [], items: [{ reasons: [reason, { ...reason, key: "inactive_threshold", policy: exceeded }],
      password_age_policy: "unknown", inactivity_policy: "exceeded", hygiene: { password_age: policy, inactivity: exceeded } }],
    collections: {}, series: {}, coverage: { hygiene_policy: { password_age: 120, inactivity: 45 } }, filter_options: {},
    limitations: [{ code: "threshold", text: "Принятая политика" }], window: {},
  };
  const localized = localizeReportResult(result);
  const reasons = localized.items[0].reasons as Array<Record<string, unknown>>;
  expect(reasons[0].qualification).toBe("Unknown: The date is missing or invalid");
  expect(reasons[0].label).toBe("Password age: unknown");
  expect(reasons[1].limitation).toContain("replication");
  expect(reasons[1].policy).toBe(exceeded);
  expect(localized.items[0].hygiene).toBe(result.items[0].hygiene);
  expect(localized.limitations[0].text).toContain("password age > 120 days; inactivity > 45 days");
  expect(reportMetadataText(result.report_key, "columns.password_age_policy.labels.unknown", "")).toBe("Unknown");
  expect(reportMetadataText(result.report_key, "columns.inactivity_policy.labels.exceeded", "")).toBe("Threshold exceeded");
});
