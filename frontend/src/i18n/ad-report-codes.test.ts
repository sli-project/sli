// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { ReportDefinitionDto, ReportResultDto } from "../api/report-v2-types";
import { en } from "./en";
import { localeRuntime, setLocale } from "./index";
import { localizeReportDefinition, localizeReportResult } from "./report-metadata";
import { ru } from "./ru";

// The locale is applied by a page reload; tests only need the stored choice.
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

const checkRow = { key: "disabled_logon", severity: "high", status: "unchanged",
  severity_text: "Высокая", status_text: "Без изменений", title: "Вход отключённой учётки",
  presentation_messages: {
    severity_text: { code: "reports.ad.checks.severity.high", params: {}, text: "Высокая" },
    status_text: { code: "reports.ad.checks.status.unchanged", params: {}, text: "Без изменений" },
    title: { code: "reports.ad.checks.users.disabled_logon.title", params: {}, text: "Вход отключённой учётки" },
  } };
const result = (report_key: string, items: Array<Record<string, unknown>>): ReportResultDto => ({ contract_id: "sli.report-result.v2", report_key,
  state: "ok", items, metrics: [], series: {}, coverage: {}, filter_options: {}, window: {}, filtered_count: items.length, has_more: false, next_cursor: null, limitations: [] });

it.each([["ru", "Высокая", "Без изменений"], ["en", "High", "Unchanged"]] as const)("shows AD check names and statuses by code in %s", (locale, severity, status) => {
  setLocale(locale);
  const [row] = localizeReportResult(result("ad.users.v2", [checkRow])).items;
  expect(row.severity_text).toBe(severity);
  expect(row.status_text).toBe(status);
  expect(row.title).toBe(locale === "ru" ? ru["reports.ad.checks.users.disabled_logon.title"] : en["reports.ad.checks.users.disabled_logon.title"]);
  // The stable codes are never replaced by display text.
  expect(row.severity).toBe("high");
  expect(row.status).toBe("unchanged");
});

it("keeps server text for a code this frontend does not know", () => {
  setLocale("en");
  const row = { status_text: "Новый статус", presentation_messages: { status_text: { code: "reports.ad.checks.status.from_a_newer_server", params: {}, text: "Новый статус" } } };
  expect(localizeReportResult(result("ad.computers.v6", [row])).items[0].status_text).toBe("Новый статус");
});

it("shows AD state rows by code, including Yes/No values", () => {
  setLocale("en");
  const row = { control_id: "dc.advertising", label: "Advertising контроллера домена", actual_value: true, actual_text: "Да",
    authority: "collector_diagnostic", authority_text: "Диагностика сборщика",
    presentation_messages: {
      label: { code: "reports.v2.ad.infrastructure.controls.dc.advertising.label", params: {}, text: "Advertising контроллера домена" },
      actual_text: { code: "reports.boolean.yes", params: {}, text: "Да" },
      authority_text: { code: "reports.v2.ad.infrastructure.authority.collector_diagnostic", params: {}, text: "Диагностика сборщика" },
    } };
  const [localized] = localizeReportResult(result("ad.infrastructure", [row])).items;
  expect(localized.label).toBe("Controller advertising");
  expect(localized.actual_text).toBe("Yes");
  expect(localized.authority_text).toBe("Collector diagnostics");
  expect(localized.actual_value).toBe(true);
});

it.each(["ru", "en"] as const)("uses dashes for missing AD values without replacing source values (%s)", (locale) => {
  setLocale(locale);
  for (const actual of [null, "not_collected", "not_evaluated", "unknown", "unavailable", "timeout", "partial", 0, false]) {
    const row = { control_id: "dc.advertising", actual_value: actual, actual_text: String(actual), qualification: "not_evaluated" };
    const [localized] = localizeReportResult(result("ad.infrastructure", [row])).items;
    expect(localized.actual_text).toBe(actual === 0 ? 0 : actual === false ? locale === "ru" ? "Нет" : "No" : "—");
    expect(localized.actual_value).toBe(actual);
    expect(localized.qualification).toBe("not_evaluated");
    expect(row.actual_text).toBe(String(actual));
  }
});

it("shows AD report titles by code when the server sent them", () => {
  setLocale("en");
  const definition = { key: "ad.infrastructure", title: "Состояние Active Directory", description: "", params: [], columns: [], views: [], presets: [],
    row_links: [], filter_options: {}, detail: false,
    presentation_messages: { title: { code: "reports.v2.ad.infrastructure.title", params: {}, text: "Состояние Active Directory" } } } as unknown as ReportDefinitionDto;
  expect(localizeReportDefinition(definition).title).toBe("Active Directory health");
});

it("keeps coded computer reason fields ahead of legacy translation and preserves source values", () => {
  setLocale("en");
  const reason = { code: "unsupported_os", label: "ОС без поддержки", observed: "Старый текст",
    operating_system: "source value must not replace message params", support_end_date: "wrong date",
    presentation_messages: {
      observed: { code: "reports.v2.ad.computers.v6.security.unsupported_os.observed",
        params: { operating_system: "Синтетическая ОС", support_end_date: "2023-10-10" }, text: "Старый текст" },
      label: { code: "reports.v2.ad.computers.v6.reasons.unsupported_os", params: {}, text: "ОС без поддержки" },
    } };
  const [row] = localizeReportResult(result("ad.computers.v6", [{ display_name: "Компьютер", reasons: [reason] }])).items;
  const [detail] = row.reasons as Array<Record<string, unknown>>;
  expect(detail.observed).toBe("Синтетическая ОС; Microsoft extended support ended on Oct 10, 2023.");
  expect(detail.operating_system).toBe(reason.operating_system);
  expect(detail.support_end_date).toBe("wrong date");
  expect(reason.presentation_messages.observed.params.support_end_date).toBe("2023-10-10");
  expect(reason.observed).toBe("Старый текст");
  expect(row.display_name).toBe("Компьютер");
  expect(row.reason_text).toBe("Unsupported OS");
});

it("preserves newer reason envelope text instead of guessing from the legacy reason code", () => {
  setLocale("en");
  const reason = { code: "unsupported_os", label: "Новая квалификация", observed: "Новые данные",
    presentation_messages: { label: { code: "future.reason.label", params: {}, text: "Новая квалификация" },
      observed: { code: "future.reason.observed", params: {}, text: "Новые данные" } } };
  const [row] = localizeReportResult(result("ad.computers.v6", [{ reasons: [reason] }])).items;
  expect((row.reasons as Array<Record<string, unknown>>)[0].observed).toBe("Новые данные");
  expect(row.reason_text).toBe("Новая квалификация");
});
