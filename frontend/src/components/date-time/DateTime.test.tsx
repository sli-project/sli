// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale, t } from "../../i18n";
import { DateTime } from "./DateTime";

afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });
it.each(["ru", "en"] as const)("localizes absent time tooltip without inventing a timestamp (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  for (const value of [undefined, null, ""]) {
    const { container, unmount } = render(<DateTime value={value} timeZone="UTC"/>);
    const time = container.querySelector("time")!;
    expect(time.title).toBe(t("operations.dateTime.notProvided"));
    expect(time.hasAttribute("datetime")).toBe(false);
    if (locale === "en") expect(time.title).not.toMatch(/[А-Яа-яЁё]/);
    unmount();
  }
});
it("preserves a supplied source timestamp in the tooltip", () => {
  const value = "2026-10-21T14:05:00Z";
  const { container } = render(<DateTime value={value} timeZone="UTC"/>);
  expect(container.querySelector("time")?.title).toBe(value);
  expect(container.querySelector("time")?.getAttribute("datetime")).toBe(value);
});
