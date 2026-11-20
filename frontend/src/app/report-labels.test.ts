// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale, t } from "../i18n";
import { objectTypeLabel, auditActionLabel, auditReasonLabel, reportSensitivityLabel, accessActionLabel } from "./report-labels";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("localizes decoy management and audit in %s", (locale) => {
  setLocale(locale);
  expect(accessActionLabel("manage_decoy")).toBe(t("decoys.manage"));
  expect(auditActionLabel("decoy_label_update")).toBe(t("decoys.changed"));
});

it.each(["ru", "en"] as const)("localizes watch management and audit in %s", (locale) => {
  setLocale(locale);
  expect(accessActionLabel("manage_watch")).toBe(t("watch.manage"));
  expect(auditActionLabel("watch_entry_update")).toBe(t("watch.changed"));
  expect(objectTypeLabel("watch_entry")).toBe(t("watch.title"));
});

it.each(["initial_owner_claimed", "auth.initial_owner.claimed"])("names owner activation action %s in both languages", (action) => {
  setLocale("ru");
  expect(auditActionLabel(action)).toBe("Активация первого владельца");
  setLocale("en");
  expect(auditActionLabel(action)).toBe("Initial owner activation");
});

it("labels the initial password change in both languages", () => {
  expect(auditActionLabel("auth.initial_admin_password.changed")).toBe("Сменён начальный пароль администратора");
  setLocale("en");
  expect(auditActionLabel("auth.initial_admin_password.changed")).toBe("Initial administrator password changed");
});

it.each([
  ["ad_group", "Группа Active Directory", "Active Directory group"],
  ["device", "Устройство", "Device"],
  ["device_identity", "Идентификатор устройства", "Device identity"],
])("names the known search type %s in both languages", (code, ru, en) => {
  setLocale("ru");
  expect(objectTypeLabel(code)).toBe(ru);
  setLocale("en");
  expect(objectTypeLabel(code)).toBe(en);
});

it("names audit actions and system grounds without rewriting user reasons", () => {
  expect(auditActionLabel("platform_setting_update")).toBe("Изменена настройка платформы");
  expect(auditActionLabel("vpn_session_evidence_grant_created")).toBe("Предоставлен доступ к сведениям о VPN-сеансе");
  expect(auditActionLabel("future_action")).toBe("future_action");
  expect(auditReasonLabel("Access allowed by assignment and capability policy")).toBe("Доступ разрешён назначением и политикой возможностей");
  expect(auditReasonLabel("Reason entered by the reviewer")).toBe("Reason entered by the reviewer");
  expect(reportSensitivityLabel("restricted")).toBe("ограниченный");
});
