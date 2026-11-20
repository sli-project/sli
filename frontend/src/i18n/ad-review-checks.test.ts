import { expect, it } from "vitest";
import { ru } from "./ru";
import { en } from "./en";

it("provides the same AD check explanations and status keys in both locales", () => {
  const keys = Object.keys(ru).filter((key) => key.startsWith("reports.ad.checks."));
  expect(keys).toContain("reports.ad.checks.status.no_comparison");
  expect(Object.keys(en).filter((key) => key.startsWith("reports.ad.checks.")).sort()).toEqual(keys.sort());
  for (const key of keys) {
    expect(ru[key as keyof typeof ru].trim()).not.toBe("");
    expect(en[key as keyof typeof en].trim()).not.toBe("");
    expect(en[key as keyof typeof en]).not.toMatch(/[А-Яа-яЁё]/);
  }
  expect(keys.filter((key) => /\.(users|computers)\..+\.why$/.test(key))).toHaveLength(20);
  for (const report of ["ad.users.v2", "ad.computers.v6"]) {
    const title = `reports.v2.${report}.views.checks.columns.check_title.label`;
    expect(ru[title as keyof typeof ru]).toBe("Проверка");
    expect(en[title as keyof typeof en]).toBe("Check");
  }
});
