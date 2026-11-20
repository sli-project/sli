import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { en } from "./en";
import { ru } from "./ru";

it.each(["ru", "en"] as const)("keeps plain AD hardening messages aligned with the server in %s", (locale) => {
  const server = JSON.parse(readFileSync(resolve(import.meta.dirname, `../../../config/i18n/server.${locale}.json`), "utf8")) as Record<string, string>;
  const dictionary = locale === "ru" ? ru : en;
  for (const [key, value] of Object.entries(server)) {
    if (!key.startsWith("security.problems.ad_hardening.")) continue;
    expect(dictionary[key as keyof typeof dictionary], key).toBe(value);
    expect(value, key).not.toMatch(/AI-assisted|ИИ-развед/);
  }
  for (const check of ["spn_users", "rc4", "unconstrained", "constrained", "laps", "old_service_password", "privileged_nonexpiring", "admin_group_size", "inactive_privileged"]) {
    for (const field of ["title", "what", "why", "action"]) {
      const key = `security.problems.ad_hardening.${check}.${field}` as keyof typeof dictionary;
      expect(dictionary[key], key).toBeTruthy();
    }
  }
  expect(dictionary["security.problems.ad_hardening.laps.none_found"]).toBeTruthy();
});
