import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { en } from "./en";
import { ru } from "./ru";

it("explains password attack observations and next steps in both languages", () => {
  const suffixes = ["spray_title", "spray_what", "spray_success_title", "spray_success_what", "spray_success_next",
    "kerberoasting_title", "kerberoasting_what", "kerberoasting_observed", "kerberoasting_why", "kerberoasting_next",
    "asrep_title", "asrep_what", "asrep_observed", "asrep_why", "asrep_next",
    "preauth_title", "preauth_what", "preauth_why", "preauth_next",
    "fanout_title", "fanout_what", "fanout_observed", "fanout_why", "fanout_next",
    "privilege_title", "privilege_what", "privilege_new_what", "privilege_why", "privilege_next", "identity_limitation",
    "brute_title", "brute_what", "disabled_title", "disabled_what",
    "password_why", "password_next", "password_limitation"] as const;
  for (const suffix of suffixes) {
    const key = `security.problems.presentation.${suffix}` as keyof typeof en;
    expect(en[key]).toBeTruthy();
    expect(ru[key as keyof typeof ru]).toBeTruthy();
    expect(en[key]).not.toEqual(ru[key as keyof typeof ru]);
  }
  expect(en["security.problems.presentation.password_limitation"]).toContain("do not prove");
});

it.each(["ru", "en"] as const)("mirrors all identity attack messages from the server in %s", (locale) => {
  const server = JSON.parse(readFileSync(resolve(import.meta.dirname, `../../../config/i18n/server.${locale}.json`), "utf8")) as Record<string, string>;
  const dictionary = locale === "ru" ? ru : en;
  for (const [key, text] of Object.entries(server)) {
    if (!key.startsWith("security.problems.presentation.")) continue;
    expect(Object.hasOwn(dictionary, key), key).toBe(true);
    expect(dictionary[key as keyof typeof dictionary], key).toBe(text);
  }
});
