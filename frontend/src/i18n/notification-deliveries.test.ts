// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { ReportDefinitionDto } from "../api/report-v2-types";
import { localeRuntime, setLocale } from ".";
import { localizeReportDefinition } from "./report-metadata";
import { en } from "./en";
import { ru } from "./ru";
import { auditActionLabel } from "../app/report-labels";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => {}); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("labels safe subscription and test audits in %s", (locale) => {
  setLocale(locale);
  const dictionary = locale === "ru" ? ru : en;
  for (const action of ["notification_subscription_update", "notification_test_enqueue", "notification_schedule_update"] as const) {
    expect(auditActionLabel(action)).toBe(dictionary[`access.audit.actions.${action}`]);
  }
});

it("keeps all delivery journal keys identical and nonempty in both languages", () => {
  const keys = (dictionary: Record<string, string>) => Object.keys(dictionary)
    .filter((key) => key.startsWith("reports.v2.notifications.deliveries.")).sort();
  expect(keys(en)).toEqual(keys(ru));
  expect(keys(en)).toHaveLength(54);
  for (const key of keys(en)) {
    expect((en as Record<string, string>)[key]).toBeTruthy();
    expect((ru as Record<string, string>)[key]).toBeTruthy();
  }
});

it("localizes simulated states without changing durable job identifiers or claiming delivery", () => {
  setLocale("en");
  const definition: ReportDefinitionDto = {
    key: "notifications.deliveries", section: "admin", title: "Журнал уведомлений",
    description: "Тестовые задания и попытки обработки. dry_run не означает доставку.",
    archetype: "monitoring-operations", params: [], views: [{ key: "table", kind: "table" }],
    row_key: "id", detail: "none", export: false, limits: { default: 50, max: 200 },
    presets: [], row_links: [], filter_options: {},
    columns: [
      { key: "id", path: "id", label: "Задание", kind: "text" },
      { key: "state", path: "state", label: "Состояние", kind: "state", labels: {
        dry_run: "Тест без отправки", blocked: "Заблокировано", retry: "Ожидает повтора", accepted: "Принято SMTP-сервером",
        delivery_unknown: "Исход отправки неизвестен",
      } },
      { key: "result_code", path: "result_code", label: "Результат", kind: "state", labels: {
        simulated: "Симуляция", smtp_outcome_unknown: "Исход отправки неизвестен", accepted: "Принято SMTP-сервером",
        telegram_chat_denied: "Чат недоступен", telegram_rate_limited: "Ограничение частоты",
        telegram_outcome_unknown: "Исход отправки неизвестен",
      } },
    ],
  };
  const localized = localizeReportDefinition(definition);
  expect(localized.title).toBe("Notification journal");
  expect(localized.description).toContain("does not mean delivery");
  expect(localized.columns[0]).toMatchObject({ key: "id", path: "id", label: "Job" });
  expect(localized.description).toContain("not proof of reading");
  expect(localized.columns[1].labels).toEqual({
    dry_run: "Test without sending", blocked: "Blocked", retry: "Awaiting retry", accepted: "Accepted by provider",
    delivery_unknown: "Submission outcome unknown",
  });
  expect(localized.columns[2].labels).toEqual({
    simulated: "Simulated", smtp_outcome_unknown: "Submission outcome unknown; check the mailbox before retrying",
    accepted: "Accepted by provider",
    telegram_chat_denied: "Telegram chat unavailable for sending",
    telegram_rate_limited: "Awaiting Telegram rate limit reset",
    telegram_outcome_unknown: "Submission outcome unknown; check the chat before retrying",
  });
  expect(definition.columns[1].labels?.dry_run).toBe("Тест без отправки");
});
