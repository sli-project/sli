// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DataTable, MetricStrip, formatCell } from "../design-system";
import { SecurityRelationsPanel } from "../app/security-events-report";
import { tableColumns } from "../app/report-v2/DetailSection";
import { formatDateTime } from "../shared/date-time";
import { collectionChannelPresentation, collectionCheckLabel, eventObservationLabel, workerNameLabel } from "../app/operations-actions";
import type { CollectorHealthItem, RuntimeWorker } from "../api/client";
import type { ReportResultDto } from "../api/report-v2-types";
import { localizeReportResult, localizeReportRow } from "./report-metadata";
import { codedText, eventFacts } from "./event-metadata";
import { localeRuntime, setLocale } from "./index";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("en"); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("localizes computer security reasons and inline evidence without exposing secrets", () => {
  const row = localizeReportRow("ad.computers.v6", { reasons: [
    { code: "unsupported_os", label: "ОС без поддержки", operating_system: "Windows 7", support_end_date: "2020-01-14",
      observed: "Исходные данные", condition: "Условие", qualification: "Вывод", limitation: "Ограничение", next_action: "Действие" },
    { code: "laps_expired", label: "Срок метаданных LAPS истёк", expiration_utc: "2026-10-07T12:00:00Z" },
    { code: "unconstrained_delegation", label: "Неограниченное делегирование" },
  ] });
  expect(row.reason_text).toBe("Unsupported OS, LAPS metadata expired, Unconstrained delegation");
  const reasons = row.reasons as Array<Record<string, string>>;
  expect(reasons[0].observed).toContain("Jan 14, 2020");
  expect(reasons[0].support_end_date).toBe("2020-01-14");
  expect(reasons[0].limitation).toContain("ESU");
  expect(reasons[1].limitation).toContain("password is never read");
  expect(reasons[2].condition).toContain("524288");
});

it.each([false, true])("renders the shared summary, unavailable dates and boolean cells in English (compact: %s)", (compact) => {
  const items = [{ key: "all", label: "Total", value: 2 }];
  const html = renderToStaticMarkup(<MetricStrip items={items} compact={compact}/>);
  expect(html).toContain('aria-label="Summary"');
  expect(html.includes('data-compact="true"')).toBe(compact);
  expect(renderToStaticMarkup(<MetricStrip items={items} compact={compact} label="Custom summary"/>)).toContain('aria-label="Custom summary"');
  expect(formatDateTime(null, "UTC")).toBe("—");
  expect(formatDateTime("invalid", "UTC")).toBe("—");
  expect(formatDateTime("2026-01-01T00:00:00Z", "invalid:TestZone")).toBe("Time zone TestZone is unavailable");
  expect(formatDateTime("2026-01-01T00:00:00Z", "TestZone")).toBe("Time zone TestZone is unavailable");
  expect(formatCell(true, "boolean")).toBe("Yes");
  expect(formatCell(false, "boolean")).toBe("No");
  expect(formatCell("Нет", "text")).toBe("Нет");
});

it("uses collection and worker codes while preserving unknown presentation and runtime identifiers", () => {
  const channel = { collection_state: "stale", collection_label: "проверка сильно отстаёт", event_observation_label: "нужна новая проверка канала" } as CollectorHealthItem;
  expect(collectionCheckLabel(channel)).toBe("check is severely overdue");
  expect(collectionChannelPresentation(channel).label).toBe("check is severely overdue");
  expect(collectionChannelPresentation(channel).tone).toBe("bad");
  const expiredBoundary = collectionChannelPresentation({ ...channel, collection_state: "current",
    last_successful_collection_utc: "2020-01-01T00:00:00Z", adaptive_action: "exit_recovery:source_boundary_reached" }, "UTC");
  expect(expiredBoundary.label).toBe("check is severely overdue");
  expect(expiredBoundary.tone).toBe("bad");
  expect(expiredBoundary.detail).toContain("Boundary read during the check at");
  expect(eventObservationLabel(channel)).toBe("a new channel check is required");
  expect(collectionCheckLabel({ ...channel, collection_state: "future" })).toBe(channel.collection_label);
  expect(collectionCheckLabel({ ...channel, collection_state: undefined })).toBe(channel.collection_label);
  const worker = { worker_name: "collection", label: "Сбор событий", worker_id: "Синтетический процесс" } as RuntimeWorker;
  expect(workerNameLabel(worker)).toBe("Event collection");
  expect(workerNameLabel({ ...worker, worker_name: "future" })).toBe(worker.label);
  expect(worker.worker_id).toBe("Синтетический процесс");
  expect(workerNameLabel({ ...worker, worker_name: "ad_snapshot_manifest_coordinator" })).toBe("Active Directory snapshot collection");
});

it("translates infrastructure controls, conditions and context labels by codes, keeping observed data", () => {
  const items = [
    { control_id: "domain.ldap_signing", authority: "report_rule_v1", label: "Требование подписывания LDAP", expected_condition: "Условие сервера", basis: "Основание сервера", entity_name: "Синтетический объект", actual_value: "required", actual_text: "required" },
    { control_id: "password.minimum_length", authority: "not_defined", label: "Минимальная длина пароля", expected_condition: "Условие сервера", basis: "Основание сервера", actual_value: 12, actual_text: "12" },
    { control_id: "dc.dns", authority: "collector_diagnostic", label: "DNS контроллера домена", expected_condition: "Условие сервера", basis: "Основание сервера", actual_value: false, actual_text: "Нет", object_context: { is_read_only: false, site_name: "Синтетический сайт" }, context: [{ code: "is_read_only", label: "RODC", value: "Нет" }, { code: "site_name", label: "Сайт", value: "Синтетический сайт" }] },
    { control_id: "replication.result_code", authority: "collector_diagnostic", label: "Код последней репликации", expected_condition: "Условие сервера", basis: "Основание сервера" },
    { control_id: "replication.last_success_freshness", authority: "report_rule_v1", label: "Свежесть успешной репликации", expected_condition: "Условие сервера", basis: "Основание сервера" },
  ];
  const localized = localizeReportResult({ report_key: "ad.infrastructure", items, metrics: [], limitations: [], filter_options: {} } as unknown as ReportResultDto);
  const rows = localized.items;
  const html = renderToStaticMarkup(<DataTable caption="Controls" rows={rows} rowKey={(row) => String(row.control_id)} columns={tableColumns([{ key: "label", label: "Control", kind: "text", path: "label" }, { key: "expected", label: "Expected", kind: "text", path: "expected_condition" }])}/>);
  expect(html).toContain("LDAP signing requirement");
  expect(html).toContain("LDAP signing must be required");
  expect(html).toContain("Organization requirement is not specified");
  expect(html).toContain(">Passed</td>");
  expect(html).toContain("The value must equal 0");
  expect(html).toContain("successful replication must be within 24 hours");
  expect(html).not.toMatch(/[А-Яа-яЁё]/);
  expect(rows[0].entity_name).toBe("Синтетический объект");
  expect(rows[2].actual_value).toBe(false);
  expect(rows[2].actual_text).toBe("No");
  expect(rows[2].context).toEqual([{ code: "is_read_only", label: "RODC", value: "No" }, { code: "site_name", label: "Site", value: "Синтетический сайт" }]);
  const unknown = { control_id: "future", label: "Исходная подпись", expected_condition: "Исходное условие", basis: "Исходное основание" };
  expect(localizeReportRow("ad.infrastructure", unknown)).toMatchObject(unknown);
  expect(items[0].label).toBe("Требование подписывания LDAP");
});

it("translates computer reasons using thresholds, preserving source descriptions and unsupported reasons", () => {
  const row = { description: "Синтетическое описание", reasons: [{ code: "stale_activity", label: "Активность старше 60 дней", threshold_days: 60 }, { code: "unknown_type", label: "Тип объекта не определён" }, { code: "unavailable_activity", label: "Нет доступной даты активности" }, { code: "unknown_os", label: "Операционная система не определена" }], quality_issues: [{ code: "source_failed", label: "Ошибка источника" }] };
  const view = localizeReportRow("ad.computers.v6", row);
  expect(view.reason_text).toBe("Activity is older than 60 days, Object type is unknown, No activity date is available, Operating system is unknown");
  expect(view.quality_text).toBe("Source error");
  expect(view.description).toBe(row.description);
  expect(localizeReportRow("ad.computers.v6", { reasons: [{ code: "future", label: "Исходная причина" }] }).reason_text).toBe("Исходная причина");
  expect(localizeReportRow("ad.computers.v6", { reasons: [{ code: "stale_activity", label: "Исходная причина" }] }).reason_text).toBe("Исходная причина");
});

it("preserves unchanged report rows and localizes only presentation in mixed results", () => {
  const data = { name: "Синтетический объект", description: "Синтетическое описание" };
  const control = { ...data, reasons: [{ code: "unknown_type", label: "Тип объекта не определён" }] };
  const result = { report_key: "ad.computers.v6", items: [data], metrics: [], limitations: [], filter_options: {}, collections: { objects: [data] } } as unknown as ReportResultDto;
  const unchanged = localizeReportResult(result);
  expect(unchanged.items).toBe(result.items);
  const mixed = { ...result, items: [data, control] };
  const localized = localizeReportResult(mixed);
  expect(localized.items).not.toBe(mixed.items);
  expect(localized.items[0]).toBe(data);
  expect(localized.items[1].reason_text).toBe("Object type is unknown");
  expect(localized.items[1].name).toBe(control.name);
  expect(localized.items[1].description).toBe(control.description);
  expect(localized.items[1].reasons).toBe(control.reasons);
  expect(localized.collections).toBe(result.collections);
  expect(control).not.toHaveProperty("reason_text");
  setLocale("ru");
  expect(localizeReportResult(mixed)).toBe(mixed);
});

it("translates coded problem descriptions and system principals while retaining arbitrary entity names", () => {
  const row = { id: 1, presentation_code: "audit_policy_changed", title: "Изменённый серверный заголовок", title_text: "Исходный заголовок", what_happened: "Описание сервера", why_text: "Пояснение сервера", next_text: "Совет сервера", actor: "sid:fixture:S-1-5-18", actor_text: "Системная учётная запись FIXTURE", entities: [{ display_name: "sid:fixture:S-1-5-18", entity_role: "actor" }, { display_name: "Синтетическая группа" }, { display_name: "42", entity_role: "source_host" }] };
  const view = localizeReportRow("security.problems", row);
  expect(view.title_text).toBe("Windows audit policy changed");
  expect([view.what_happened, view.why_text, view.next_text].join(" ")).not.toMatch(/[А-Яа-яЁё]/);
  expect(view.actor_text).toBe("System account FIXTURE");
  expect(view.entity_text).toBe("System account FIXTURE, Синтетическая группа, Source server");
  expect(localizeReportRow("security.problems", { title: "Синтетическое правило", title_text: "Синтетический заголовок" }).title_text).toBe("Синтетический заголовок");
});

it("translates coded event fact labels and coverage disclaimers, preserving raw values and legacy fallback", () => {
  const semantics = { title_code: "Security:Microsoft-Windows-Security-Auditing:4719.title", facts: [["Событие", "Изменена политика аудита"], ["Сервер", "Синтетический сервер"]] as Array<[string, string]>, fact_label_codes: ["facts.event", "facts.server"] };
  expect(eventFacts(semantics)).toEqual([["Event", "Audit policy changed"], ["Server", "Синтетический сервер"]]);
  expect(eventFacts({ facts: semantics.facts })).toEqual(semantics.facts);
  expect(codedText("security.events.chains.coverage.limitations.bounded_retained_page", "Исходное пояснение")).toContain("authorized bounded page");
  expect(codedText("security.events.chains.coverage.limitations.no_completeness_proof", "Исходное пояснение")).toContain("does not prove");
  expect(codedText("security.events.chains.coverage.limitations.future", "Исходное пояснение")).toBe("Исходное пояснение");
  setLocale("ru");
  expect(eventFacts(semantics)).toEqual(semantics.facts);
});

it("renders coded retained coverage limitations with an unknown-code fallback", () => {
  const html = renderToStaticMarkup(<SecurityRelationsPanel items={[]} state="empty" loading={false} failed={false} hasMore={false} fetchingMore={false} fetchMore={() => undefined}
    filters={{ timeFrom: "2026-01-01T00:00:00Z", timeTo: "2026-01-02T00:00:00Z", timeZone: "UTC", category: "", eventId: "", outcome: "", actor: "", target: "", group: "", source: "", q: "", limit: 20 }}
    coverage={{ state: "available", limitation_codes: ["bounded_retained_page", "no_completeness_proof", "future"], limitations: ["Покрытие относится только к разрешённой ограниченной странице сохранённых связей.", "Тестовый или пустой результат не доказывает наличие либо полноту retained-истории.", "Неизвестное пояснение"] }}/>
  );
  expect(html).toContain("Coverage applies only to the authorized bounded page of retained relations.");
  expect(html).toContain("A test or empty result does not prove the presence or completeness of retained history.");
  expect(html).toContain("Неизвестное пояснение");
  expect(html).not.toContain("Покрытие относится");
});
