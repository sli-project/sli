// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { ReportDefinitionDto } from "../api/report-v2-types";
import { localeRuntime, setLocale } from ".";
import { localizeReportDefinition } from "./report-metadata";
import { en } from "./en";
import { ru } from "./ru";
import { accessActionLabel, auditActionLabel } from "../app/report-labels";
import { reportTraceGrantLabel } from "../app/report-access-trace";
import type { V4ReportAccessTrace } from "../api/client";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => {}); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("localizes the channel journal without changing kind or secret references", () => {
  setLocale("en");
  const definition: ReportDefinitionDto = {
    key: "notifications.channels", section: "admin", title: "Каналы уведомлений",
    description: "Реестр каналов почты и Telegram. Доставка ещё не настроена.",
    archetype: "monitoring-operations", params: [], views: [{ key: "table", kind: "table" }],
    row_key: "kind", detail: "none", export: false, limits: { default: 2, max: 2 },
    presets: [], row_links: [], filter_options: {},
    columns: [
      { key: "kind", path: "kind", label: "Канал", kind: "state", labels: { smtp: "Почта", telegram: "Telegram" } },
      { key: "state", path: "state", label: "Состояние", kind: "state", labels: { not_configured: "Не настроен" } },
      { key: "secret_ref", path: "secret_ref", label: "Ссылка на секрет", kind: "text" },
    ],
  };
  const localized = localizeReportDefinition(definition);
  expect(localized.title).toBe("Notification channels");
  expect(localized.description).toContain("not configured");
  expect(localized.columns[0].labels).toEqual({ smtp: "Email", telegram: "Telegram" });
  expect(localized.columns[1].labels).toEqual({ not_configured: "Not configured" });
  expect(localized.columns[2].key).toBe("secret_ref");
  expect(localized.columns[2].label).toBe("Secret reference");
  expect(definition.columns[0].labels?.smtp).toBe("Почта");
});

it("keeps all channel journal keys identical and nonempty in both languages", () => {
  const keys = (dictionary: Record<string, string>) => Object.keys(dictionary)
    .filter((key) => key.startsWith("reports.v2.notifications.channels.")).sort();
  expect(keys(en)).toEqual(keys(ru));
  expect(keys(en)).toHaveLength(17);
  for (const key of keys(en)) {
    expect((en as Record<string, string>)[key]).toBeTruthy();
    expect((ru as Record<string, string>)[key]).toBeTruthy();
  }
});

it.each([
  ["ru", "Настройка канала уведомлений", "Изменены метаданные канала уведомлений"],
  ["en", "Configure notification channel", "Notification channel metadata updated"],
] as const)("labels the channel permission and safe audit in %s", (locale, action, audit) => {
  setLocale(locale);
  expect(accessActionLabel("configure_channel")).toBe(action);
  expect(auditActionLabel("notification_channel_update")).toBe(audit);
  const grant = { source_type: "direct", source: "current_subject", scope: { kind: "all" },
    field_categories: ["technical"], allowed_actions: ["configure_channel"] } as V4ReportAccessTrace["grants"][number];
  expect(reportTraceGrantLabel(grant).actions).toBe(action);
});
