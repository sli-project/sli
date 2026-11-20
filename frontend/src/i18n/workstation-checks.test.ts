import { existsSync, readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { en } from "./en";
import { ru } from "./ru";

it("distinguishes C03 received and outgoing failures and labels counts as lower bounds in ru/en", () => {
  const catalogRoot = existsSync("config/i18n") ? "config/i18n" : "../config/i18n";
  for (const [locale, messages] of [["ru", ru], ["en", en]] as const) {
    const server: Record<string, string> = JSON.parse(readFileSync(`${catalogRoot}/server.${locale}.json`, "utf8"));
    for (const direction of ["on_station", "from_station"] as const) {
      const key = `workstations.directions.${direction}` as const;
      expect(messages[key].trim()).not.toBe("");
      expect(server[key]).toBe(messages[key]);
    }
    expect(messages["workstations.directions.on_station"]).not.toBe(messages["workstations.directions.from_station"]);
    expect(server["workstations.reasons.password_failures"]).toBe(messages["workstations.reasons.password_failures"]);
  }
  expect(ru["workstations.reasons.password_failures"]).toContain("не менее {count}");
  expect(en["workstations.reasons.password_failures"]).toContain("at least {count}");
});

it("explains incomplete device history without claiming a first-ever connection", () => {
  expect(ru["workstations.reasons.device_history_incomplete"]).toContain("первое подключение");
  expect(en["workstations.reasons.device_history_incomplete"]).toContain("first connection");
});

it("distinguishes C05 creation, updates and removal and explains the inventory limit in ru/en", () => {
  for (const change of ["service_installed", "task_created", "task_deleted", "task_updated", "task_enabled", "task_disabled"]) {
    const key = `workstations.reasons.${change}` as keyof typeof ru;
    expect(ru[key].trim()).not.toBe("");
    expect(en[key].trim()).not.toBe("");
  }
  expect(ru["workstations.reasons.service_task_baseline_unknown"]).toContain("дату события");
  expect(en["workstations.reasons.service_task_baseline_unknown"]).toContain("event date");
  expect(en["workstations.reasons.service_task_baseline_unknown"]).toContain("do not prove a shared cause");
});

it("explains observed protection enabling in both languages", () => {
  expect(ru["workstations.reasons.protection_enabled"]).toContain("{components}");
  expect(en["workstations.reasons.protection_enabled"]).toContain("{components}");
});

it("explains C07 local time, policy version and unknown working hours in both languages", () => {
  for (const messages of [ru, en]) {
    for (const parameter of ["local_time", "timezone", "policy_version"]) {
      expect(messages["workstations.reasons.logon_outside_policy"]).toContain(`{${parameter}}`);
    }
    expect(messages["workstations.reasons.logon_policy_not_configured"].trim()).not.toBe("");
    expect(messages["workstations.reasons.logon_type_unknown"].trim()).not.toBe("");
  }
});

it("provides all ten workstation check explanations and matching reason parameters in ru/en", () => {
  const keys = Object.keys(ru).filter((key) => key.startsWith("workstations."));
  expect(keys.length).toBeGreaterThanOrEqual(50);
  expect(Object.keys(en).filter((key) => key.startsWith("workstations.")).sort()).toEqual(keys.sort());
  for (let number = 1; number <= 10; number++) {
    for (const field of ["title", "why", "action", "remediation"]) {
      expect(keys).toContain(`workstations.checks.C${String(number).padStart(2, "0")}.${field}`);
    }
  }
  for (const key of keys) {
    const messageKey = key as keyof typeof ru;
    expect(ru[messageKey].trim()).not.toBe("");
    expect(en[messageKey].trim()).not.toBe("");
    expect(en[messageKey]).not.toMatch(/[А-Яа-яЁё]/);
    expect(en[messageKey].match(/\{\w+\}/g)?.sort() ?? [])
      .toEqual(ru[messageKey].match(/\{\w+\}/g)?.sort() ?? []);
  }
});

it("explains C02 removal and unknown initial membership in both languages", () => {
  for (const key of ["workstations.reasons.local_admin_removed", "workstations.reasons.local_admin_baseline_unknown"] as const) {
    expect(ru[key].trim()).not.toBe("");
    expect(en[key].trim()).not.toBe("");
  }
  expect(en["workstations.reasons.local_admin_baseline_unknown"]).toContain("event date");
  expect(ru["workstations.reasons.local_admin_baseline_unknown"]).toContain("дату события");
});

it("labels missing C04 signature evidence without asserting an unsigned file", () => {
  const root = existsSync("config/i18n") ? "config/i18n" : "../config/i18n";
  for (const [locale, messages] of [["ru", ru], ["en", en]] as const) {
    const server = JSON.parse(readFileSync(`${root}/server.${locale}.json`, "utf8"));
    expect(server["workstations.process.signature_not_received"])
      .toBe(messages["workstations.process.signature_not_received"]);
  }
  expect(ru["workstations.process.signature_not_received"]).toContain("не получены");
  expect(en["workstations.process.signature_not_received"]).toContain("not received");
});
