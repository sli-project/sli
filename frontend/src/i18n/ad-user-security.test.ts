// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { ReportResultDto } from "../api/report-v2-types";
import { localeRuntime, setLocale, t, type MessageKey } from ".";
import { localizeReportResult, reportMetadataText } from "./report-metadata";
import { ru } from "./ru";
import { en } from "./en";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

const reasonKeys = ["password_not_required", "kerberos_no_preauth", "spn_privileged", "spn_old_password", "privileged_password_never_expires"];
const evidence = { uac: 4194848, spn: ["HTTP/service.invalid"], password_last_set: "2020-01-01T00:00:00Z", snapshot_at: "2026-10-16T00:00:00Z" };
function page(): ReportResultDto {
  const reasons = reasonKeys.map((key) => ({ key,
    label: ru[`reports.v2.ad.users.v2.params.reason.options.${key}` as MessageKey],
    summary: "Сводка", observed: "Наблюдение", condition: "Условие", qualification: "Причина",
    limitation: "Ограничение", next: "Проверить", severity: key === "spn_old_password" ? "medium" : "high", evidence }));
  return { contract_id: "sli.report-result.v2", report_key: "ad.users.v2", state: "ok", has_more: false, next_cursor: null,
    filtered_count: 1, metrics: [], items: [{ display_name: "Synthetic service", reasons, review_details: reasons,
      reason_keys: reasonKeys, reason_text: reasons.map((reason) => reason.label).join(", "), admin_count: 1,
      flags: [ru["reports.v2.ad.users.v2.flags.smartcard_required"], ru["reports.v2.ad.users.v2.flags.account_not_delegated"]] }],
    collections: {}, series: {}, coverage: {}, filter_options: {}, limitations: [], window: {} };
}

it.each(["ru", "en"] as const)("presents each security reason, severity and evidence in %s", (locale) => {
  setLocale(locale);
  const original = page();
  const localized = localizeReportResult(original);
  const reasons = localized.items[0].reasons as Record<string, unknown>[];
  reasons.forEach((reason, index) => {
    expect(reason.label).toBe(t(`reports.v2.ad.users.v2.params.reason.options.${reasonKeys[index]}` as MessageKey));
    expect(reason.severity).toBe(original.items[0].reasons instanceof Array ? original.items[0].reasons[index].severity : undefined);
    expect(reason.evidence).toBe(evidence);
    if (locale === "en") {
      for (const field of ["condition", "qualification", "limitation", "next", "observed"]) expect(String(reason[field])).not.toMatch(/[А-Яа-яЁё]/);
      expect(reason.observed).toContain(evidence.snapshot_at);
      expect(reason.observed).toContain(evidence.spn[0]);
      expect(reason.observed).toContain(evidence.password_last_set);
    }
  });
  expect(localized.items[0].display_name).toBe("Synthetic service");
  expect(localized.items[0].admin_count).toBe(1);
  if (locale === "en") {
    expect(localized.items[0].review_details).toEqual(reasons);
    expect(localized.items[0].reason_text).toContain("AS-REP roasting");
    expect(reportMetadataText("ad.users.v2", "detail.columns.severity.labels.high", "")).toBe("High");
    expect(reportMetadataText("ad.users.v2", "columns.service_account_type.labels.gmsa", "")).toBe("gMSA");
  } else expect(localized).toBe(original);
});

it("localizes protective flags even when an account has no attention reasons", () => {
  setLocale("en");
  const result = page();
  result.items[0] = { ...result.items[0], reasons: [], review_details: [] };
  expect(localizeReportResult(result).items[0].flags).toEqual(["Smart card required", "Sensitive account, cannot be delegated"]);
});

it.each([undefined, [], ["Synthetic future flag"]])("preserves unchanged rows and items with flags %j", (flags) => {
  setLocale("en");
  const result = page();
  const reasons = [{ key: "future", label: "Synthetic reason" }];
  const row = { reasons, reason_text: "Synthetic reason", ...(flags ? { flags } : {}) };
  result.items = [row];
  const localized = localizeReportResult(result);
  expect(localized.items).toBe(result.items);
  expect(localized.items[0]).toBe(row);
  expect(localized.items[0].reasons).toBe(reasons);
});

it("keeps matching non-empty Russian and English security and exception keys", () => {
  const keys = (messages: Record<string, string>) => Object.keys(messages).filter((key) =>
    key.startsWith("platformSettings.service_exceptions.") || key.startsWith("reports.v2.ad.users.v2.security.") ||
    key.startsWith("reports.v2.ad.users.v2.flags.") || reasonKeys.some((reason) => key.endsWith(`params.reason.options.${reason}`))).sort();
  expect(keys(en)).toEqual(keys(ru));
  for (const key of keys(ru)) { expect(ru[key as MessageKey]).toBeTruthy(); expect(en[key as MessageKey]).toBeTruthy(); }
});
