import { expect, it } from "vitest";
import { ru } from "./ru";
import { en } from "./en";

it("offers an explicit proxy remedy for network and timeout failures in both locales", () => {
  for (const key of ["notify.telegram.error.network", "notify.telegram.error.timeout"] as const) {
    expect(ru[key]).toMatch(/прокси/i);
    expect(en[key]).toMatch(/proxy/i);
  }
});