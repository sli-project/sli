// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale, t } from "../i18n";
import { UiKitPage } from "./UiKitPage";

const charts = vi.hoisted(() => ({ specs: [] as unknown[] }));
vi.mock("../design-system", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../design-system")>()),
  Chart: ({ title, spec }: { title: string; spec: unknown }) => { charts.specs.push(spec); return <h2>{title}</h2>; },
}));
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); charts.specs = []; });

it.each(["ru", "en"] as const)("localizes the exposed demo route without changing synthetic source names in %s", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const { container } = render(<UiKitPage/>);
  expect(screen.getByRole("heading", { name: t("uiKit.title"), level: 1 })).toBeTruthy();
  expect(screen.getByLabelText(t("uiKit.theme"))).toBeTruthy();
  expect(screen.getByLabelText(t("uiKit.density"))).toBeTruthy();
  const sourceName = "очень-длинное-имя-компьютера-для-проверки-переноса.example.test";
  expect(container.textContent).toContain(sourceName);
  expect(JSON.stringify(charts.specs)).toContain(t("uiKit.successfulLogons"));
  if (locale === "en") {
    expect(container.textContent?.replaceAll(sourceName, "")).not.toMatch(/[А-Яа-яЁё]/);
    expect(JSON.stringify(charts.specs)).toContain('"Mon"');
    expect(JSON.stringify(charts.specs)).not.toMatch(/[А-Яа-яЁё]/);
  }
});
