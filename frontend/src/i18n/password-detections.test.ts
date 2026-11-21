import { expect, it } from "vitest";
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
