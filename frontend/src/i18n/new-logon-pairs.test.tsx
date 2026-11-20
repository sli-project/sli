// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import type { ReportDefinitionDto, ReportResultDto } from "../api/report-v2-types";
import { columnValue, defaultValues, fillTemplate, filterFields } from "../app/report-v2/state";
import { localeRuntime, setLocale, t } from "./index";
import { ru } from "./ru";
import { en } from "./en";
import { localizeReportDefinition, localizeReportResult } from "./report-metadata";

const prefix = "reports.v2.ad.new-logon-pairs.";
const definition: ReportDefinitionDto = {
  key: "ad.new-logon-pairs", title: ru["reports.v2.ad.new-logon-pairs.title"], description: ru["reports.v2.ad.new-logon-pairs.description"],
  section: "reports/computers", archetype: "investigation-evidence", params: [
    { key: "period", kind: "period", label: ru["reports.v2.ad.new-logon-pairs.params.period.label"], default: "24h", presets: ["24h", "7d", "custom"] },
    { key: "baseline_days", kind: "int", label: ru["reports.v2.ad.new-logon-pairs.params.baseline_days.label"], default: 30 },
  ], columns: [{ key: "novelty", label: ru["reports.v2.ad.new-logon-pairs.columns.novelty.label"], kind: "state", path: "novelty",
    labels: { new_user: ru["reports.v2.ad.new-logon-pairs.columns.novelty.labels.new_user"], new_pair: ru["reports.v2.ad.new-logon-pairs.columns.novelty.labels.new_pair"], no_baseline: ru["reports.v2.ad.new-logon-pairs.columns.novelty.labels.no_baseline"] } }],
  views: [], row_key: "id", detail: "none", export: false, limits: { default: 50, max: 200 }, presets: [], filter_options: {},
  row_links: [{ label: ru["reports.v2.ad.new-logon-pairs.row_links./app/events/{source_event_id}"], href: "/app/events/{source_event_id}" }],
};

afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("keeps matching locale keys and editable baseline defaults on the shared report renderer", () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  const keys = Object.keys(ru).filter((key) => key.startsWith(prefix));
  expect(keys.length).toBeGreaterThan(20);
  expect(keys.sort()).toEqual(Object.keys(en).filter((key) => key.startsWith(prefix)).sort());
  expect(defaultValues(definition)).toEqual({ period: { preset: "24h" }, baseline_days: "30" });
  expect(filterFields(definition)[1]).toMatchObject({ key: "baseline_days", kind: "text" });
  for (const locale of ["ru", "en"] as const) {
    setLocale(locale);
    const localized = localizeReportDefinition(definition);
    expect(columnValue(localized.columns[0], { novelty: "no_baseline" })).toBe(locale === "ru" ? "Новизна не определена" : "Novelty undetermined");
    expect(columnValue(localized.columns[0], { novelty: "new_pair" })).toBe(locale === "ru" ? "Новая пара" : "New pair");
    expect(localized.title).toBe(t("shell.nav.new-logon-pairs-report"));
    expect(fillTemplate(localized.row_links[0].href, { source_event_id: 123 })).toBe("/app/events/123");
    expect(fillTemplate("/app/entities/{user_entity_id}", { user_entity_id: null })).toBeNull();
    const raw = { report_key: definition.key, items: [{ user: "TEST\\user-1", novelty: "no_baseline" }],
      metrics: [{ key: "history_from", label: ru["reports.v2.ad.new-logon-pairs.metrics.history_from.label"], value: "2026-10-01T00:00:00+00:00" }],
      limitations: [{ code: "no_baseline", text: ru["reports.v2.ad.new-logon-pairs.limitations.no_baseline"] }], filter_options: {} } as unknown as ReportResultDto;
    const data = localizeReportResult(raw);
    expect(data.items).toBe(raw.items);
    expect(data.metrics[0].value).toBe(raw.metrics[0].value);
    expect(data.metrics[0].label).toBe(locale === "ru" ? "История доступна с (UTC)" : "History available from (UTC)");
    if (locale === "en") expect(data.limitations[0].text).not.toMatch(/[А-Яа-яЁё]/);
  }
});

it("localizes actionable history/context failures and distinguishes empty history", () => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  const codes = ["history_empty", "history_not_enabled", "history_not_configured", "history_read_failed",
    "history_verification_failed", "users_context_missing", "computers_context_missing", "domain_controllers_missing",
    "context_read_failed", "context_read_timeout", "context_read_cancelled", "computer_inventory_unavailable", "read_timeout", "read_cancelled"] as const;
  for (const locale of ["ru", "en"] as const) {
    setLocale(locale);
    for (const code of codes) {
      const raw = { report_key: definition.key, items: [], metrics: [], limitations: [{ code, text: ru[`${prefix}limitations.${code}`] }],
        filter_options: {} } as unknown as ReportResultDto;
      const text = localizeReportResult(raw).limitations[0].text;
      expect(text).not.toBe("fallback");
      expect(text).toBe(t(`${prefix}limitations.${code}`));
      if (locale === "en") expect(text).not.toMatch(/[А-Яа-яЁё]/);
    }
  }
});

